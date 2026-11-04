package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/bradleyfalzon/ghinstallation/v2"
	gogithub "github.com/google/go-github/v72/github"
)

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
	return flag.NewFlagSet(name, flag.ContinueOnError)
}

// subcommands maps a CLI verb to its handler. Each is driven by a GitHub Action.
var subcommands = map[string]func([]string) error{
	"triage-comment": runTriageComment,
	"pr-merged":      runPRMerged,
}

func usage() string {
	return "usage: glvd2-bot <triage-comment|pr-merged> [flags]"
}

func main() {
	if len(os.Args) < 2 {
		slog.Error(usage())
		os.Exit(2) //nolint:mnd // conventional CLI usage exit code
	}

	run, ok := subcommands[os.Args[1]]
	if !ok {
		slog.Error("unknown subcommand", slog.String("subcommand", os.Args[1]), slog.String("usage", usage()))
		os.Exit(2) //nolint:mnd // conventional CLI usage exit code
	}

	if err := run(os.Args[2:]); err != nil {
		slog.Error(os.Args[1]+" failed", slog.Any("error", err))
		os.Exit(1)
	}
}
