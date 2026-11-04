package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/gardenlinux/glvd2/internal/bot"
)

// runPRMerged is the CLI entry point for the PR-merge GitHub Action.
// It scans a merged pull request's body for CVE IDs and closes the matching
// issue for each one, posting a comment linking back to the PR.
func runPRMerged(args []string) error {
	fs := newFlagSet("pr-merged")
	prURL := fs.String("pr-url", "", "HTML URL of the merged pull request")
	prBody := fs.String("pr-body", "", "Body text of the merged pull request")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// body can be passed via --pr-body flag or PR_BODY env var;
	// the env var is preferred for multiline content from GitHub Actions
	body := *prBody
	if body == "" {
		body = os.Getenv("PR_BODY")
	}
	if *prURL == "" {
		return errors.New("--pr-url is required")
	}

	issueRepoOwner := mustEnv("ISSUE_REPO_OWNER")
	issueRepoName := mustEnv("ISSUE_REPO_NAME")

	gh, err := newGitHubClient()
	if err != nil {
		return fmt.Errorf("could not create GitHub client: %w", err)
	}

	ctx := context.Background()
	issues := bot.NewIssueService(gh, issueRepoOwner, issueRepoName)

	var firstErr error
	for _, cveID := range bot.ExtractCVEIDs(body) {
		if err := issues.CloseIssue(ctx, cveID, *prURL); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}
