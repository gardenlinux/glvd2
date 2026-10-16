package whttp

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShouldRetry(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		resp   Response
		err    error
		expect bool
	}{
		{"transport error", Response{HTTPStatusCode: 0}, assert.AnError, true},
		{"too many requests", Response{HTTPStatusCode: http.StatusTooManyRequests}, nil, true},
		{"server error", Response{HTTPStatusCode: 503}, nil, true},
		{
			"rate-limited 403",
			Response{HTTPStatusCode: http.StatusForbidden, Header: http.Header{"X-Ratelimit-Remaining": {"0"}}},
			nil,
			true,
		},
		{"plain 403", Response{HTTPStatusCode: http.StatusForbidden, Header: http.Header{}}, nil, false},
		{"not found", Response{HTTPStatusCode: 404}, nil, false},
		{"ok", Response{HTTPStatusCode: 200}, nil, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expect, shouldRetry(tc.resp, tc.err))
		})
	}
}

func TestRetryDelay_HonorsRetryAfter(t *testing.T) {
	t.Parallel()

	resp := Response{Header: http.Header{"Retry-After": {"2"}}}
	assert.Equal(t, 2*time.Second, retryDelay(resp, time.Second, 3))
}

func TestRetryDelay_ExponentialFallback(t *testing.T) {
	t.Parallel()

	resp := Response{Header: http.Header{}}
	assert.Equal(t, 4*time.Second, retryDelay(resp, time.Second, 2))
}

func TestRetryDelay_CapsHintedWaitsAtHintCeiling(t *testing.T) {
	t.Parallel()

	resp := Response{Header: http.Header{"Retry-After": {"100000"}}}
	assert.Equal(t, maxHintDelay, retryDelay(resp, time.Second, 0))
}

func TestRetryDelay_HonorsHintBeyondBackoffCap(t *testing.T) {
	t.Parallel()

	// A 10-minute hint exceeds maxRetryDelay (2m) but is below maxHintDelay (1h),
	// so it must be honored rather than clamped to the backoff cap.
	resp := Response{Header: http.Header{"Retry-After": {"600"}}}
	assert.Equal(t, 10*time.Minute, retryDelay(resp, time.Second, 0))
}

func TestRetryDelay_RetryAfterOverflowClamped(t *testing.T) {
	t.Parallel()

	// A value large enough to overflow secs*time.Second must be clamped, not wrapped.
	resp := Response{Header: http.Header{"Retry-After": {"99999999999"}}}
	assert.Equal(t, maxHintDelay, retryDelay(resp, time.Second, 0))
}

func TestRetryDelay_CapsBackoff(t *testing.T) {
	t.Parallel()

	resp := Response{Header: http.Header{}}
	assert.Equal(t, maxRetryDelay, retryDelay(resp, time.Minute, 10))
}

func TestGet_RetriesRateLimitThenSucceeds(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	client := &HTTPClient{MaxRetries: 3, BaseDelay: time.Millisecond}
	resp, err := client.GetResponse(t.Context(), srv.URL)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.HTTPStatusCode)
	assert.Equal(t, int32(2), calls.Load())
}

func TestGet_DoesNotRetryNotFound(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := &HTTPClient{MaxRetries: 3, BaseDelay: time.Millisecond}
	resp, _ := client.GetResponse(t.Context(), srv.URL)

	assert.Equal(t, http.StatusNotFound, resp.HTTPStatusCode)
	assert.Equal(t, int32(1), calls.Load())
}
