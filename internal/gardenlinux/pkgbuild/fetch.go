package pkgbuild

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gardenlinux/glvd2/internal/github"
	"github.com/gardenlinux/glvd2/internal/whttp"
)

const (
	githubOwner   = "gardenlinux"
	githubAPIBase = "https://api.github.com"
)

// GitHubFetcher reads pkg-build inputs from GL package repos via the GitHub API.
type GitHubFetcher struct {
	client  *whttp.HTTPClient
	baseURL string
}

// NewGitHubFetcher builds a [GitHubFetcher] using an authenticated GitHub client.
func NewGitHubFetcher() (*GitHubFetcher, error) {
	client, err := github.NewClient()
	if err != nil {
		return nil, err
	}

	return &GitHubFetcher{client: client, baseURL: githubAPIBase}, nil
}

type commitRef struct {
	SHA string `json:"sha"`
}

// CommitForTag resolves a tag to its commit sha via the commits API, which accepts a tag ref directly.
func (f *GitHubFetcher) CommitForTag(ctx context.Context, repo, tag string) (string, error) {
	endpoint := fmt.Sprintf("%s/repos/%s/%s/commits/%s", f.baseURL, githubOwner, repo, url.PathEscape(tag))

	resp, err := f.client.GetResponse(ctx, endpoint)
	switch {
	case err != nil:
		return "", err
	case resp.HTTPStatusCode == http.StatusNotFound:
		return "", ErrNotFound
	case resp.HTTPStatusCode != http.StatusOK:
		return "", fmt.Errorf("resolving %s@%s: unexpected status %d", repo, tag, resp.HTTPStatusCode)
	}

	var ref commitRef
	if unmarshalErr := json.Unmarshal(resp.Body, &ref); unmarshalErr != nil {
		return "", fmt.Errorf("decoding commit for %s@%s: %w", repo, tag, unmarshalErr)
	}

	return ref.SHA, nil
}

type contentFile struct {
	Type     string `json:"type"`
	Encoding string `json:"encoding"`
	Content  string `json:"content"`
}

// File fetches a text file at a ref via the contents API, decoding base64 content.
func (f *GitHubFetcher) File(ctx context.Context, repo, path, ref string) (string, error) {
	endpoint := fmt.Sprintf(
		"%s/repos/%s/%s/contents/%s?ref=%s",
		f.baseURL, githubOwner, repo, escapePath(path), url.QueryEscape(ref),
	)

	resp, err := f.client.GetResponse(ctx, endpoint)
	switch {
	case err != nil:
		return "", err
	case resp.HTTPStatusCode == http.StatusNotFound:
		return "", ErrNotFound
	case resp.HTTPStatusCode != http.StatusOK:
		return "", fmt.Errorf("fetching %s:%s@%s: unexpected status %d", repo, path, ref, resp.HTTPStatusCode)
	}

	var file contentFile
	if unmarshalErr := json.Unmarshal(resp.Body, &file); unmarshalErr != nil {
		return "", fmt.Errorf("decoding %s:%s@%s: %w", repo, path, ref, unmarshalErr)
	}
	if file.Type != "file" {
		return "", fmt.Errorf("%s:%s@%s is not a file (type %q)", repo, path, ref, file.Type)
	}
	if file.Encoding != "base64" {
		return "", fmt.Errorf("%s:%s@%s has unexpected encoding %q", repo, path, ref, file.Encoding)
	}

	// The contents API wraps base64 content in newlines; strip them before decoding.
	encoded := strings.NewReplacer("\n", "", "\r", "").Replace(file.Content)
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decoding base64 of %s:%s@%s: %w", repo, path, ref, err)
	}

	return string(decoded), nil
}

// escapePath percent-escapes each segment of a contents API path
// while preserving the slash separators between segments.
func escapePath(path string) string {
	segments := strings.Split(path, "/")
	for i, segment := range segments {
		segments[i] = url.PathEscape(segment)
	}

	return strings.Join(segments, "/")
}
