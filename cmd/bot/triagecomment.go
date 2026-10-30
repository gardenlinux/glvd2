package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/gardenlinux/glvd2/internal/bot"
	gogithub "github.com/google/go-github/v72/github"
)

// runTriageComment is the CLI entry point for the GitHub Action.
// It reads a single issue comment, parses commands from it, applies them
// to the assessment record, and writes the result back.
func runTriageComment(args []string) error {
	fs := newFlagSet("triage-comment")
	cveID := fs.String("cve-id", "", "CVE ID (e.g. CVE-2024-1234)")
	actor := fs.String("actor", "", "GitHub login of the comment author")
	commentIDStr := fs.String("comment-id", "", "GitHub comment ID")
	issueNumberStr := fs.String("issue-number", "", "GitHub issue number")
	body := fs.String("body", "", "Comment body text")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *cveID == "" || *actor == "" || *commentIDStr == "" {
		return errors.New("--cve-id, --actor and --comment-id are required")
	}

	// body can be passed via --body flag or TRIAGE_COMMENT_BODY env var;
	// the env var is preferred for multiline content from GitHub Actions
	commentBody := *body
	if commentBody == "" {
		commentBody = os.Getenv("TRIAGE_COMMENT_BODY")
	}
	if commentBody == "" {
		return errors.New("comment body must be provided via --body or TRIAGE_COMMENT_BODY")
	}

	commentID, err := strconv.ParseInt(*commentIDStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid --comment-id: %w", err)
	}
	issueNumber := 0
	if *issueNumberStr != "" {
		n, err := strconv.Atoi(*issueNumberStr)
		if err != nil {
			return fmt.Errorf("invalid --issue-number: %w", err)
		}
		issueNumber = n
	}

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
		return fmt.Errorf("could not create GitHub client: %w", err)
	}

	ctx := context.Background()
	return applyTriageComment(ctx, gh,
		org, securityTeam,
		issueRepoOwner, issueRepoName,
		assessmentRepoOwner, assessmentRepoName,
		*cveID, *actor, commentID, issueNumber, commentBody,
	)
}

func applyTriageComment(
	ctx context.Context,
	gh *gogithub.Client,
	org, securityTeam string,
	issueRepoOwner, issueRepoName string,
	assessmentRepoOwner, assessmentRepoName string,
	cveID, actor string,
	commentID int64,
	issueNumber int,
	body string,
) error {
	issues := bot.NewIssueService(gh, issueRepoOwner, issueRepoName)
	assessments := bot.NewAssessmentRepoService(gh, assessmentRepoOwner, assessmentRepoName)

	reply := func(msg string) {
		if issueNumber == 0 {
			slog.Info("bot reply", slog.String("message", msg))
			return
		}
		_, _, err := gh.Issues.CreateComment(ctx, issueRepoOwner, issueRepoName, issueNumber,
			&gogithub.IssueComment{Body: gogithub.Ptr(msg)})
		if err != nil {
			slog.Error("could not post reply comment", slog.Any("error", err))
		}
	}

	cmds, reopen, parseErrs := bot.ParseCommands(body)

	// /reopen is handled at the issue level and does not require team membership
	if reopen != nil {
		if err := issues.ReopenIssue(ctx, cveID, reopen.Reason, actor); err != nil {
			reply(":x: Could not reopen: " + err.Error())
			return err
		}
		return nil
	}

	if len(cmds) == 0 {
		return nil
	}

	member, err := bot.IsTeamMember(ctx, gh, org, securityTeam, actor)
	if err != nil {
		reply(fmt.Sprintf(":x: Could not verify team membership for @%s: %s", actor, err))
		return err
	}
	if !member {
		reply(fmt.Sprintf(":no_entry: @%s is not a member of the security team and cannot apply triage commands.", actor))
		return nil
	}

	rec, sha, err := assessments.ReadAssessment(ctx, cveID)
	if errors.Is(err, bot.ErrAssessmentNotFound) {
		rec = bot.NewAssessmentRecord(cveID, issueNumber, time.Now().UTC())
		sha = ""
	} else if err != nil {
		reply(fmt.Sprintf(":x: Could not read assessment for %s: %s", cveID, err))
		return err
	}

	cmdCtx := bot.CommandContext{
		Actor:        actor,
		IssueComment: commentID,
		Now:          time.Now().UTC(),
	}

	_, applyErr := bot.ApplyCommands(rec, cmds, cmdCtx)
	for _, e := range parseErrs {
		reply(":x: Command parse error: " + e.Error())
	}
	if applyErr != nil {
		reply(":x: " + applyErr.Error())
		return applyErr
	}

	if err = assessments.WriteAssessment(ctx, rec, sha); err != nil {
		reply(fmt.Sprintf(":x: Could not write assessment for %s: %s", cveID, err))
		return err
	}

	if syncErr := issues.EnsureIssue(ctx, rec); syncErr != nil {
		slog.Warn("could not sync issue body", slog.String("cve_id", cveID), slog.Any("error", syncErr))
	}

	slog.Info("updated assessment", slog.String("cve_id", cveID), slog.String("actor", actor))
	reply(":white_check_mark: Recorded assessment for " + cveID + ".")
	return nil
}
