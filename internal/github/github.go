package github

import (
	"errors"
	"log/slog"
	"os"

	httpclient "github.com/gardenlinux/glvd2/internal/whttp"
)

func NewClient() (*httpclient.HTTPClient, error) {
	token := os.Getenv("GH_TOKEN")
	if token == "" {
		return nil, errors.New("env GH_TOKEN is missing")
	}

	client := httpclient.NewClient()
	client.Headers.Set("Accept", "application/vnd.github+json")
	client.Headers.Set("Authorization", "Bearer "+token)
	client.Headers.Set("X-GitHub-Api-Version", "2026-03-10")
	slog.Debug("created new github http client with auth token")

	return client, nil
}
