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
		slog.With("client", "github").Error("GH_TOKEN is missing")
		return nil, errors.New("Env GH_TOKEN is missing")
	}

	client := httpclient.NewClient()
	client.Headers = append(client.Headers, httpclient.MakeHeader("Accept", "application/vnd.github+json"))
	client.Headers = append(client.Headers, httpclient.MakeHeader("Authorization", "Bearer "+token))
	client.Headers = append(client.Headers, httpclient.MakeHeader("X-GitHub-Api-Version", "2026-03-10"))
	slog.With("client", "github").Debug("new http client with auth token")
	return client, nil
}
