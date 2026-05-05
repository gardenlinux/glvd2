package whttp

// Wrapped HTTP client with prepared Get-Methods

import (
	"context"
	"io"
	"log/slog"
	"net/http"
)

type Header struct {
	key   string
	value string
}

type HTTPClient struct {
	Token   string
	Headers []Header
}

func MakeHeader(key, value string) Header {
	return Header{
		key:   key,
		value: value,
	}
}

func (h *HTTPClient) Get(url string) (*[]byte, error) {
	slog.With("client", "http", "method", "get", "url", url).Info("Performing request")
	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	for _, header := range h.Headers {
		req.Header.Set(header.key, header.value)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close() //nolint:errcheck // Ignore errors on close

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Error("Could not read body",
			slog.String("url", url),
			slog.Any("error", err))
		return nil, err
	}

	return &body, err
}

func NewClient() *HTTPClient {
	httpClient := HTTPClient{}
	return &httpClient
}
