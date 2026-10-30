package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/awslabs/aws-lambda-go-api-proxy/httpadapter"
	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/gardenlinux/glvd2/internal/bot"
	"github.com/gardenlinux/glvd2/internal/config"
	gogithub "github.com/google/go-github/v72/github"
)

type server struct {
	gh             *gogithub.Client
	issues         *bot.IssueService
	assessmentRepo *bot.AssessmentRepoService
	org            string
	securityTeam   string
	webhookSecret  []byte
}

func (s *server) handleWebhook(w http.ResponseWriter, r *http.Request) {
	payload, err := gogithub.ValidatePayload(r, s.webhookSecret)
	if err != nil {
		slog.Warn("invalid webhook payload", slog.Any("error", err))
		http.Error(w, "invalid payload", http.StatusUnauthorized)
		return
	}

	event, err := gogithub.ParseWebHook(gogithub.WebHookType(r), payload)
	if err != nil {
		slog.Warn("could not parse webhook", slog.Any("error", err))
		http.Error(w, "parse error", http.StatusBadRequest)
		return
	}

	switch e := event.(type) {
	case *gogithub.IssueCommentEvent:
		if e.GetAction() != "created" {
			return
		}
		s.handleIssueComment(r.Context(), e)
	case *gogithub.PullRequestEvent:
		if e.GetAction() == "closed" && e.GetPullRequest().GetMerged() {
			s.handlePRMerged(r.Context(), e)
		}
	default:
		// unhandled event type — nothing to do
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleIssueComment(ctx context.Context, e *gogithub.IssueCommentEvent) {
	actor := e.GetSender().GetLogin()
	repoOwner := e.GetRepo().GetOwner().GetLogin()
	repoName := e.GetRepo().GetName()
	issueNumber := e.GetIssue().GetNumber()
	issueTitle := e.GetIssue().GetTitle()
	commentID := e.GetComment().GetID()
	body := e.GetComment().GetBody()

	cveID := extractCVEID(issueTitle)
	if cveID == "" {
		return
	}

	cmds, errs := bot.ParseCommands(body)
	for _, err := range errs {
		s.replyToIssue(ctx, repoOwner, repoName, issueNumber,
			":x: Command parse error: "+err.Error())
	}
	if len(cmds) == 0 {
		return
	}

	// /reopen is handled at the issue level and does not require team membership
	for _, cmd := range cmds {
		if r, ok := cmd.(bot.ReopenCommand); ok {
			if err := s.issues.ReopenIssue(ctx, cveID, r.Reason, actor); err != nil {
				s.replyToIssue(ctx, repoOwner, repoName, issueNumber,
					":x: Could not reopen: "+err.Error())
			}
			return
		}
	}

	// all other commands require security-team membership
	member, err := bot.IsTeamMember(ctx, s.gh, s.org, s.securityTeam, actor)
	if err != nil {
		slog.Error("could not check team membership", slog.String("actor", actor), slog.Any("error", err))
		s.replyToIssue(ctx, repoOwner, repoName, issueNumber,
			fmt.Sprintf(":x: Could not verify team membership for @%s: %s", actor, err))
		return
	}
	if !member {
		s.replyToIssue(ctx, repoOwner, repoName, issueNumber,
			fmt.Sprintf(":no_entry: @%s is not a member of the security team and cannot apply triage commands.", actor))
		return
	}

	rec, sha, err := s.assessmentRepo.ReadAssessment(ctx, cveID)
	if errors.Is(err, bot.ErrAssessmentNotFound) {
		rec = bot.NewAssessmentRecord(cveID, issueNumber, time.Now().UTC())
		sha = ""
	} else if err != nil {
		slog.Error("could not read assessment", slog.String("cve_id", cveID), slog.Any("error", err))
		s.replyToIssue(ctx, repoOwner, repoName, issueNumber,
			fmt.Sprintf(":x: Could not read assessment for %s: %s", cveID, err))
		return
	}

	cmdCtx := bot.CommandContext{
		Actor:        actor,
		IssueComment: commentID,
		Now:          time.Now().UTC(),
	}

	for _, cmd := range cmds {
		if applyErr := cmd.Apply(rec, cmdCtx); applyErr != nil {
			s.replyToIssue(ctx, repoOwner, repoName, issueNumber,
				":x: "+applyErr.Error())
			return
		}
	}

	if err = s.assessmentRepo.WriteAssessment(ctx, rec, sha); err != nil {
		slog.Error("could not write assessment", slog.String("cve_id", cveID), slog.Any("error", err))
		s.replyToIssue(ctx, repoOwner, repoName, issueNumber,
			fmt.Sprintf(":x: Could not write assessment for %s: %s", cveID, err))
		return
	}

	if syncErr := s.issues.EnsureIssue(ctx, rec); syncErr != nil {
		slog.Warn("could not sync issue body", slog.String("cve_id", cveID), slog.Any("error", syncErr))
	}

	slog.Info("updated assessment", slog.String("cve_id", cveID), slog.String("actor", actor))
	s.replyToIssue(ctx, repoOwner, repoName, issueNumber,
		":white_check_mark: Recorded assessment for "+cveID+".")
}

func (s *server) handlePRMerged(ctx context.Context, e *gogithub.PullRequestEvent) {
	pr := e.GetPullRequest()
	body := pr.GetBody()
	prURL := pr.GetHTMLURL()

	for _, cveID := range bot.ExtractCVEIDs(body) {
		if err := s.issues.CloseIssue(ctx, cveID, prURL); err != nil {
			slog.Error("could not close issue after PR merge",
				slog.String("cve_id", cveID), slog.Any("error", err))
		}
	}
}

// handleIngest accepts a JSON array of CVE IDs and creates or updates a GitHub issue for each one.
func (s *server) handleIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var cveIDs []string
	if err := json.NewDecoder(r.Body).Decode(&cveIDs); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	var failed []string
	for _, cveID := range cveIDs {
		if !bot.IsValidCVEID(cveID) {
			slog.Warn("skipping invalid CVE ID", slog.String("cve_id", cveID))
			failed = append(failed, cveID)
			continue
		}

		rec, _, err := s.assessmentRepo.ReadAssessment(r.Context(), cveID)
		if errors.Is(err, bot.ErrAssessmentNotFound) {
			rec = bot.NewAssessmentRecord(cveID, 0, time.Now().UTC())
		} else if err != nil {
			slog.Error("could not read assessment for ingest",
				slog.String("cve_id", cveID), slog.Any("error", err))
			failed = append(failed, cveID)
			continue
		}

		if err = s.issues.EnsureIssue(r.Context(), rec); err != nil {
			slog.Error("could not ensure issue",
				slog.String("cve_id", cveID), slog.Any("error", err))
			failed = append(failed, cveID)
		}
	}
	if len(failed) > 0 {
		w.WriteHeader(http.StatusMultiStatus)
		if encErr := json.NewEncoder(w).Encode(map[string][]string{"failed": failed}); encErr != nil {
			slog.Warn("could not encode error response", slog.Any("error", encErr))
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) replyToIssue(ctx context.Context, owner, repo string, number int, body string) {
	_, _, err := s.gh.Issues.CreateComment(ctx, owner, repo, number, &gogithub.IssueComment{
		Body: gogithub.Ptr(body),
	})
	if err != nil {
		slog.Error("could not post comment", slog.Any("error", err))
	}
}

func extractCVEID(title string) string {
	candidate, _, _ := strings.Cut(title, " ")
	candidate = strings.TrimSuffix(candidate, ":")
	if bot.IsValidCVEID(candidate) {
		return candidate
	}
	return ""
}

func newGitHubClient() (*gogithub.Client, error) {
	appIDStr := os.Getenv("GITHUB_APP_ID")
	installIDStr := os.Getenv("GITHUB_INSTALLATION_ID")
	privateKeyPath := os.Getenv("GITHUB_PRIVATE_KEY_PATH")

	if appIDStr == "" || installIDStr == "" || privateKeyPath == "" {
		return nil, errors.New("GITHUB_APP_ID, GITHUB_INSTALLATION_ID and GITHUB_PRIVATE_KEY_PATH must be set")
	}

	var appID, installID int64
	if _, err := fmt.Sscan(appIDStr, &appID); err != nil {
		return nil, fmt.Errorf("invalid GITHUB_APP_ID: %w", err)
	}
	if _, err := fmt.Sscan(installIDStr, &installID); err != nil {
		return nil, fmt.Errorf("invalid GITHUB_INSTALLATION_ID: %w", err)
	}

	itr, err := ghinstallation.NewKeyFromFile(http.DefaultTransport, appID, installID, privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("could not create GitHub App transport: %w", err)
	}

	return gogithub.NewClient(&http.Client{Transport: itr}), nil
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		slog.Error("required environment variable not set", slog.String("var", key))
		os.Exit(1)
	}
	return v
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	return fs
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "triage-comment" {
		if err := runTriageComment(os.Args[2:]); err != nil {
			slog.Error("triage-comment failed", slog.Any("error", err))
			os.Exit(1)
		}
		return
	}

	runServer()
}

func runServer() {
	cfg, err := config.LoadAppConfig("./config")
	if err != nil {
		slog.Error("could not load config", slog.Any("error", err))
		os.Exit(1)
	}
	_ = cfg // cfg reserved for future use (e.g. assessment repo path overrides)

	webhookSecret := mustEnv("GITHUB_WEBHOOK_SECRET")
	org := mustEnv("GITHUB_ORG")
	issueRepoOwner := mustEnv("ISSUE_REPO_OWNER")
	issueRepoName := mustEnv("ISSUE_REPO_NAME")
	assessmentRepoOwner := mustEnv("ASSESSMENT_REPO_OWNER")
	assessmentRepoName := mustEnv("ASSESSMENT_REPO_NAME")
	securityTeam := os.Getenv("SECURITY_TEAM_SLUG")
	if securityTeam == "" {
		securityTeam = "security-team"
	}

	gh, err := newGitHubClient()
	if err != nil {
		slog.Error("could not create GitHub client", slog.Any("error", err))
		os.Exit(1)
	}

	srv := &server{
		gh:             gh,
		issues:         bot.NewIssueService(gh, issueRepoOwner, issueRepoName),
		assessmentRepo: bot.NewAssessmentRepoService(gh, assessmentRepoOwner, assessmentRepoName),
		org:            org,
		securityTeam:   securityTeam,
		webhookSecret:  []byte(webhookSecret),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/webhook", srv.handleWebhook)
	mux.HandleFunc("/ingest", srv.handleIngest)

	if os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "" {
		slog.Info("starting in Lambda mode")
		lambda.Start(httpadapter.New(mux).ProxyWithContext)
		return
	}

	addr := ":8080"
	if port := os.Getenv("PORT"); port != "" {
		addr = ":" + port
	}
	slog.Info("bot listening", slog.String("addr", addr))
	if err = http.ListenAndServe(addr, mux); err != nil { //nolint:gosec // addr is internal
		slog.Error("server error", slog.Any("error", err))
		os.Exit(1)
	}
}
