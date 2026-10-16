// Package whttp provides a wrapped HTTP GET client
// with retry and pagination handling plus GitHub rate-limit awareness.
package whttp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gardenlinux/glvd2/internal/logging"
)

// Retry defaults for transient failures and GitHub rate limiting.
const (
	defaultMaxRetries = 4
	defaultBaseDelay  = time.Second
	defaultTimeout    = 60 * time.Second
	maxRetryDelay     = 2 * time.Minute
	// maxHintDelay bounds a server-provided wait (Retry-After, X-RateLimit-Reset).
	maxHintDelay = time.Hour
)

const maxBodyBytes = 30 * 1024 * 1024

var linkHeaderRegexp = regexp.MustCompile(`<([^>]+)>;\s*rel="([^"]+)"`)

type HTTPClient struct {
	Headers    http.Header
	MaxRetries int
	BaseDelay  time.Duration
	Client     *http.Client
}

// Response with consumed body payload.
type Response struct {
	Header         http.Header
	LinkHeader     LinkHeader
	HTTPStatusCode int
	Body           []byte
}

type LinkHeader struct {
	Prev  string
	Next  string
	First string
	Last  string
}

func NewClient() *HTTPClient {
	return &HTTPClient{
		Headers:    make(http.Header),
		MaxRetries: defaultMaxRetries,
		BaseDelay:  defaultBaseDelay,
		Client:     &http.Client{Timeout: defaultTimeout},
	}
}

func (h *HTTPClient) get(ctx context.Context, url string) (Response, error) {
	maxAttempts := max(h.MaxRetries+1, 1)

	var resp Response
	var err error
	for attempt := range maxAttempts {
		resp, err = h.getOnce(ctx, url)
		if attempt == maxAttempts-1 || !shouldRetry(resp, err) {
			return resp, err
		}

		delay := retryDelay(resp, h.BaseDelay, attempt)
		slog.Warn("retrying HTTP request",
			slog.String("url", url),
			slog.Int("status", resp.HTTPStatusCode),
			slog.Int("attempt", attempt+1),
			slog.Duration("delay", delay))

		select {
		case <-ctx.Done():
			return resp, ctx.Err()
		case <-time.After(delay):
		}
	}

	return resp, err
}

// getOnce performs a single GET attempt.
// It returns an error only for request-build, transport, or body-read failures.
func (h *HTTPClient) getOnce(ctx context.Context, url string) (Response, error) {
	slog.Debug("performing request",
		slog.String("client", "http"),
		slog.String("method", "GET"),
		slog.String("url", url))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		slog.Error("could not create request",
			slog.String("client", "http"),
			slog.String("method", "GET"),
			slog.String("url", url),
			slog.Any("error", err))
		return Response{}, err
	}

	for key, values := range h.Headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	resp, err := h.client().Do(req)
	if err != nil {
		slog.Error("could not perform request",
			slog.String("client", "http"),
			slog.String("method", "GET"),
			slog.String("url", url),
			slog.Any("error", err))
		return Response{}, err
	}

	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			slog.Error("could not close response body",
				slog.String("client", "http"),
				slog.String("url", url),
				slog.Any("error", closeErr))
		}
	}()

	body, err := io.ReadAll(http.MaxBytesReader(nil, resp.Body, maxBodyBytes))
	if err != nil {
		slog.Error("could not read response body",
			slog.String("client", "http"),
			slog.String("url", url),
			slog.Any("error", err))
		return Response{Header: resp.Header, HTTPStatusCode: resp.StatusCode}, err
	}

	return Response{
		Header:         resp.Header,
		LinkHeader:     parseLink(resp.Header),
		HTTPStatusCode: resp.StatusCode,
		Body:           body,
	}, nil
}

func (h *HTTPClient) client() *http.Client {
	if h.Client != nil {
		return h.Client
	}
	return &http.Client{Timeout: defaultTimeout}
}

func (h *HTTPClient) GetRaw(ctx context.Context, url string) ([]byte, int, error) {
	response, err := h.get(ctx, url)
	if err != nil {
		return nil, response.HTTPStatusCode, err
	}
	if err = statusError(response.HTTPStatusCode); err != nil {
		return nil, response.HTTPStatusCode, err
	}

	return response.Body, response.HTTPStatusCode, nil
}

func (h *HTTPClient) GetString(ctx context.Context, url string) (string, int, error) {
	response, err := h.get(ctx, url)
	if err != nil {
		return "", response.HTTPStatusCode, err
	}
	if err = statusError(response.HTTPStatusCode); err != nil {
		return "", response.HTTPStatusCode, err
	}

	return string(response.Body), response.HTTPStatusCode, nil
}

func (h *HTTPClient) GetResponse(ctx context.Context, url string) (Response, error) {
	return h.get(ctx, url)
}

// GetJSON fetches the URL and decodes the JSON body into a value of type T.
// It allocates the target internally so callers cannot accidentally pass a
// non-pointer, and returns the decoded value along with the raw response.
//
//nolint:ireturn // generic T return is intentional
func GetJSON[T any](ctx context.Context, h *HTTPClient, url string) (T, Response, error) {
	var target T

	response, err := h.get(ctx, url)
	if err != nil {
		return target, response, err
	}
	if err = statusError(response.HTTPStatusCode); err != nil {
		return target, response, err
	}

	slog.Log(ctx, logging.LevelTrace, "payload", slog.String("url", url), slog.String("body", string(response.Body)))

	if err = json.Unmarshal(response.Body, &target); err != nil {
		return target, response, fmt.Errorf("decoding JSON from %q: %w", url, err)
	}

	return target, response, nil
}

// statusError reports a non-2xx/3xx status as an error for the convenience getters.
func statusError(code int) error {
	if code >= http.StatusBadRequest {
		return fmt.Errorf("HTTP status code %d indicates error", code)
	}

	return nil
}

func parseLink(header http.Header) LinkHeader {
	var result LinkHeader

	linkStr := header.Get(
		"link", //nolint: revive,canonicalheader,nolintlint // see: Link Pagination in Github API
	)
	for item := range strings.SplitSeq(linkStr, ",") {
		// now having: <https://api.github.com/organizations/61944014/repos?type=public&page=1&per_page=100>;
		// rel=\"first\"
		item = strings.TrimSpace(item)
		matches := linkHeaderRegexp.FindStringSubmatch(item)

		if len(matches) > 2 { //nolint: mnd,revive,nolintlint // must match comment above
			switch matches[2] {
			case "next":
				result.Next = matches[1]
			case "prev":
				result.Prev = matches[1]
			case "first":
				result.First = matches[1]
			case "last":
				result.Last = matches[1]
			default:
				slog.Error("unknown link relation", slog.String("item", item))
			}
		}
	}

	return result
}

// shouldRetry reports whether a response warrants another attempt.
func shouldRetry(resp Response, err error) bool {
	if err != nil && resp.HTTPStatusCode == 0 {
		return true // transport-level failure with no status
	}

	switch {
	case resp.HTTPStatusCode == http.StatusForbidden && isRateLimited(resp.Header):
		return true
	case resp.HTTPStatusCode == http.StatusTooManyRequests:
		return true
	case resp.HTTPStatusCode >= http.StatusInternalServerError:
		return true
	default:
		return false
	}
}

// isRateLimited reports whether a 403 is a GitHub rate-limit response
// rather than a plain authorization failure.
func isRateLimited(header http.Header) bool {
	if header == nil {
		return false
	}

	if header.Get("Retry-After") != "" {
		return true
	}

	return header.Get("X-Ratelimit-Remaining") == "0"
}

// retryDelay derives the wait before the next attempt. A server-provided hint
// (Retry-After, X-RateLimit-Reset) is honored up to maxHintDelay; otherwise it
// falls back to exponential backoff capped at maxRetryDelay.
func retryDelay(resp Response, base time.Duration, attempt int) time.Duration {
	if base <= 0 {
		base = defaultBaseDelay
	}

	if d, ok := hintedDelay(resp.Header); ok {
		return capDelay(d, maxHintDelay)
	}

	return capDelay(base<<attempt, maxRetryDelay)
}

// hintedDelay extracts a server-provided wait from Retry-After (seconds) or X-RateLimit-Reset (epoch seconds).
func hintedDelay(header http.Header) (time.Duration, bool) {
	if header == nil {
		return 0, false
	}

	if ra := header.Get("Retry-After"); ra != "" {
		if secs, err := strconv.Atoi(strings.TrimSpace(ra)); err == nil && secs >= 0 {
			// Clamp before converting, so secs*time.Second cannot overflow int64.
			if maxSecs := int(maxHintDelay / time.Second); secs > maxSecs {
				secs = maxSecs
			}

			return time.Duration(secs) * time.Second, true
		}
	}

	if reset := header.Get("X-Ratelimit-Reset"); reset != "" {
		if epoch, err := strconv.ParseInt(strings.TrimSpace(reset), 10, 64); err == nil {
			if d := time.Until(time.Unix(epoch, 0)); d > 0 {
				return d, true
			}
			return 0, true
		}
	}

	return 0, false
}

func capDelay(d, maxDelay time.Duration) time.Duration {
	if d < 0 {
		return 0
	}
	if d > maxDelay {
		return maxDelay
	}

	return d
}
