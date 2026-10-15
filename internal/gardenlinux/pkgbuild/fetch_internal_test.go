package pkgbuild

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gardenlinux/glvd2/internal/whttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestFetcher wires a GitHubFetcher to a test server, disabling retry backoff
// so transient-status cases return promptly.
func newTestFetcher(t *testing.T, handler http.Handler) *GitHubFetcher {
	t.Helper()

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	client := whttp.NewClient()
	client.MaxRetries = 0
	client.BaseDelay = time.Millisecond

	return &GitHubFetcher{client: client, baseURL: srv.URL}
}

func TestGitHubFetcher_CommitForTag(t *testing.T) {
	t.Parallel()

	f := newTestFetcher(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/repos/gardenlinux/package-openssl/commits/3.5.5-1gl1", r.URL.Path)
		_, _ = w.Write([]byte(`{"sha":"some-sha"}`))
	}))

	sha, err := f.CommitForTag(t.Context(), "package-openssl", "3.5.5-1gl1")
	require.NoError(t, err)
	assert.Equal(t, "some-sha", sha)
}

func TestGitHubFetcher_CommitForTag_NotFound(t *testing.T) {
	t.Parallel()

	f := newTestFetcher(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))

	_, err := f.CommitForTag(t.Context(), "package-openssl", "9.9.9")
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestGitHubFetcher_CommitForTag_UnexpectedStatus(t *testing.T) {
	t.Parallel()

	f := newTestFetcher(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
	}))

	_, err := f.CommitForTag(t.Context(), "package-openssl", "bad")
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrNotFound)
	assert.Contains(t, err.Error(), "unexpected status 422")
}

// TestGitHubFetcher_CommitForTag_TransportError guards the switch ordering.
// A transport failure (no HTTP response) must surface the transport error and should
// not be masked as an "unexpected status 0".
func TestGitHubFetcher_CommitForTag_TransportError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Close() // closed up front so the request fails at the transport layer

	client := whttp.NewClient()
	client.MaxRetries = 0
	f := &GitHubFetcher{client: client, baseURL: srv.URL}

	_, err := f.CommitForTag(t.Context(), "package-openssl", "1.0")
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrNotFound)
	assert.NotContains(t, err.Error(), "unexpected status")
}

func TestGitHubFetcher_File(t *testing.T) {
	t.Parallel()

	const content = "apt_src openssl\napply_patches\n"
	f := newTestFetcher(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/repos/gardenlinux/package-openssl/contents/patches-debian/series", r.URL.Path)
		assert.Equal(t, "3.5.5-1gl1", r.URL.Query().Get("ref"))
		// Mimic the GitHub contents API wrapping base64 content in newlines.
		encoded := base64.StdEncoding.EncodeToString([]byte(content))
		_, _ = w.Write([]byte(`{"type":"file","encoding":"base64","content":"` + encoded + `\n"}`))
	}))

	got, err := f.File(t.Context(), "package-openssl", "patches-debian/series", "3.5.5-1gl1")
	require.NoError(t, err)
	assert.Equal(t, content, got)
}

func TestGitHubFetcher_File_NotFound(t *testing.T) {
	t.Parallel()

	f := newTestFetcher(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))

	_, err := f.File(t.Context(), "package-openssl", "prepare_source", "1.0")
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestGitHubFetcher_File_RejectsNonFile(t *testing.T) {
	t.Parallel()

	f := newTestFetcher(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"type":"dir"}`))
	}))

	_, err := f.File(t.Context(), "package-openssl", "patches", "1.0")
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrNotFound)
	assert.Contains(t, err.Error(), "is not a file")
}
