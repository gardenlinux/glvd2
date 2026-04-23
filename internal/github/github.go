package github

import (
	"log/slog"
	"os"

	httpclient "github.com/gardenlinux/glvd2/internal/whttp"
)

func NewClient() *httpclient.HTTPClient {
	token := os.Getenv("GH_TOKEN")
	if token == "" {
		slog.With("client", "github").Error("GH_TOKEN is missing")
		panic("GH_TOKEN is missing")
	}

	client := httpclient.NewClient()
	client.Headers = append(client.Headers, httpclient.MakeHeader("Accept", "application/vnd.github+json"))
	client.Headers = append(client.Headers, httpclient.MakeHeader("Authorization", "Bearer "+token))
	client.Headers = append(client.Headers, httpclient.MakeHeader("X-GitHub-Api-Version", "2026-03-10"))
	slog.With("client", "github").Debug("new http client with auth token")
	return client
}
