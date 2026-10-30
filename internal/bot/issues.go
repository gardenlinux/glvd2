package bot

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/gardenlinux/glvd2/internal/assessment"
	gogithub "github.com/google/go-github/v72/github"
)

var cveIDInTextRegex = regexp.MustCompile(`CVE-\d{4}-\d+`)

// IssueService creates and updates GitHub issues for CVEs.
type IssueService struct {
	gh        *gogithub.Client
	repoOwner string
	repoName  string
}

func NewIssueService(gh *gogithub.Client, repoOwner, repoName string) *IssueService {
	return &IssueService{gh: gh, repoOwner: repoOwner, repoName: repoName}
}

// cveLabel returns the unique label name used to identify an issue for a given CVE.
func cveLabel(cveID string) string {
	return "cve-id:" + cveID
}

// EnsureIssue creates a GitHub issue for the CVE if one does not exist yet.
// If an issue already exists (identified by its label), the body is updated.
func (s *IssueService) EnsureIssue(ctx context.Context, rec *assessment.Record) error {
	label := cveLabel(rec.ID)

	existing, err := s.findIssue(ctx, label)
	if err != nil {
		return err
	}

	title := issueTitle(rec)
	body := issueBody(rec)

	if existing == nil {
		if err = s.ensureLabel(ctx, label); err != nil {
			return err
		}
		_, _, err = s.gh.Issues.Create(ctx, s.repoOwner, s.repoName, &gogithub.IssueRequest{
			Title:  gogithub.Ptr(title),
			Body:   gogithub.Ptr(body),
			Labels: &[]string{label, "cve"},
		})
		if err != nil {
			return fmt.Errorf("could not create issue for %s: %w", rec.ID, err)
		}
		slog.Info("created issue", slog.String("cve_id", rec.ID))
		return nil
	}

	// update body if the issue already exists
	_, _, err = s.gh.Issues.Edit(
		ctx,
		s.repoOwner,
		s.repoName,
		existing.GetNumber(),
		&gogithub.IssueRequest{
			Title: gogithub.Ptr(title),
			Body:  gogithub.Ptr(body),
		},
	)
	if err != nil {
		return fmt.Errorf("could not update issue for %s: %w", rec.ID, err)
	}
	slog.Info("updated issue", slog.String("cve_id", rec.ID))
	return nil
}

// ErrIssueNotFound is returned when no issue exists for a given CVE label.
var ErrIssueNotFound = errors.New("issue not found")

// findIssue returns (nil, nil) when no issue matches the label, and (issue, nil) when found.
func (s *IssueService) findIssue(ctx context.Context, label string) (*gogithub.Issue, error) {
	opts := &gogithub.IssueListByRepoOptions{
		Labels:      []string{label},
		State:       "all",
		ListOptions: gogithub.ListOptions{PerPage: 1},
	}
	issues, _, err := s.gh.Issues.ListByRepo(ctx, s.repoOwner, s.repoName, opts)
	if err != nil {
		return nil, fmt.Errorf("could not search issues for label %s: %w", label, err)
	}
	if len(issues) == 0 {
		return nil, nil
	}
	return issues[0], nil
}

// ensureLabel creates the per-CVE label if it doesn't exist yet.
func (s *IssueService) ensureLabel(ctx context.Context, label string) error {
	_, resp, err := s.gh.Issues.GetLabel(ctx, s.repoOwner, s.repoName, label)
	if err == nil {
		return nil
	}
	if resp == nil || resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("could not check label %s: %w", label, err)
	}
	_, _, err = s.gh.Issues.CreateLabel(ctx, s.repoOwner, s.repoName, &gogithub.Label{
		Name:  gogithub.Ptr(label),
		Color: gogithub.Ptr("e11d48"),
	})
	if err != nil {
		return fmt.Errorf("could not create label %s: %w", label, err)
	}
	return nil
}

func issueTitle(rec *assessment.Record) string {
	title := rec.ID
	if rec.Upstream.Description != "" {
		// use first sentence of description as subtitle, capped at 80 runes
		sub := []rune(rec.Upstream.Description)
		if i := strings.IndexByte(rec.Upstream.Description, '.'); i > 0 && i < 80 { //nolint:mnd // visual cap
			sub = sub[:i+1]
		} else if len(sub) > 80 { //nolint:mnd
			sub = append(sub[:80], '…')
		}
		title += ": " + string(sub)
	}
	return title
}

func issueBody(rec *assessment.Record) string {
	var b strings.Builder

	if rec.Upstream.Description != "" {
		fmt.Fprintf(&b, "%s\n\n", rec.Upstream.Description)
	}

	if rec.Upstream.CVSSv3 != nil {
		fmt.Fprintf(&b, "**CVSS v3 base score:** %.1f\n\n", rec.Upstream.CVSSv3.Score)
	} else if rec.Upstream.CVSSv4 != nil {
		fmt.Fprintf(&b, "**CVSS v4 base score:** %.1f\n\n", rec.Upstream.CVSSv4.Score)
	}

	status := rec.GetGlobalStatus()
	if status != "" {
		fmt.Fprintf(&b, "**Garden Linux status:** %s\n", status)
		if rec.Manual.ManualTriage.Justification != "" {
			fmt.Fprintf(&b, "**Justification:** %s\n", rec.Manual.ManualTriage.Justification)
		}
		b.WriteString("\n")
	}

	if rec.Manual.Notes != "" {
		fmt.Fprintf(&b, "**Notes:** %s\n\n", rec.Manual.Notes)
	}

	b.WriteString("---\n")
	if path, err := assessment.Path("data", rec.ID); err == nil {
		fmt.Fprintf(&b, "_Assessment file: `%s`_\n\n", path)
	}

	b.WriteString(commandsReference())

	return b.String()
}

// ExtractCVEIDs returns all CVE IDs found anywhere in text.
func ExtractCVEIDs(text string) []string {
	return cveIDInTextRegex.FindAllString(text, -1)
}

// CloseIssue finds the open issue for cveID and closes it, posting a comment with prURL.
func (s *IssueService) CloseIssue(ctx context.Context, cveID, prURL string) error {
	issue, err := s.findIssue(ctx, cveLabel(cveID))
	if err != nil {
		return fmt.Errorf("could not find issue for %s: %w", cveID, err)
	}
	if issue == nil || issue.GetState() == "closed" {
		slog.Info("no open issue found, skipping close", slog.String("cve_id", cveID))
		return nil
	}

	comment := fmt.Sprintf(
		":white_check_mark: Closing: a fix for %s was merged in %s.\n\n"+
			"If this CVE is not fully addressed, use `/reopen <reason>` to reopen.",
		cveID, prURL)
	_, _, err = s.gh.Issues.CreateComment(ctx, s.repoOwner, s.repoName, issue.GetNumber(),
		&gogithub.IssueComment{Body: gogithub.Ptr(comment)})
	if err != nil {
		return fmt.Errorf("could not comment on issue for %s: %w", cveID, err)
	}

	_, _, err = s.gh.Issues.Edit(ctx, s.repoOwner, s.repoName, issue.GetNumber(),
		&gogithub.IssueRequest{State: gogithub.Ptr("closed")})
	if err != nil {
		return fmt.Errorf("could not close issue for %s: %w", cveID, err)
	}

	slog.Info("closed issue", slog.String("cve_id", cveID), slog.String("pr", prURL))
	return nil
}

// ReopenIssue finds the issue for cveID (open or closed) and reopens it.
func (s *IssueService) ReopenIssue(ctx context.Context, cveID, reason, actor string) error {
	issue, err := s.findIssue(ctx, cveLabel(cveID))
	if err != nil {
		return fmt.Errorf("could not find issue for %s: %w", cveID, err)
	}
	if issue == nil {
		return fmt.Errorf("no issue found for %s", cveID)
	}
	if issue.GetState() == "open" {
		return nil
	}

	comment := fmt.Sprintf(":warning: Reopened by @%s: %s", actor, reason)
	_, _, err = s.gh.Issues.CreateComment(ctx, s.repoOwner, s.repoName, issue.GetNumber(),
		&gogithub.IssueComment{Body: gogithub.Ptr(comment)})
	if err != nil {
		return fmt.Errorf("could not comment on issue for %s: %w", cveID, err)
	}

	_, _, err = s.gh.Issues.Edit(ctx, s.repoOwner, s.repoName, issue.GetNumber(),
		&gogithub.IssueRequest{State: gogithub.Ptr("open")})
	if err != nil {
		return fmt.Errorf("could not reopen issue for %s: %w", cveID, err)
	}

	slog.Info("reopened issue", slog.String("cve_id", cveID), slog.String("actor", actor))
	return nil
}
