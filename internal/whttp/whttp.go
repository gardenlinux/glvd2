package whttp

// Wrapped HTTP client with prepared Get-Methods

import (
	"context"
	"encoding/json"
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

// type HttpResponse struct {
// 	Header     []http.Header
// 	StatusCode int
// 	Body       string
// }

func MakeHeader(key, value string) Header {
	return Header{
		key:   key,
		value: value,
	}
}

func (h *HTTPClient) GetString(url string) (string, int, error) {
	result, httpStatus, err := h.Get(url)
	if err != nil {
		return "", httpStatus, err
	}

	return string(*result), httpStatus, nil
}

func (h *HTTPClient) GetJSON(url string, target interface{}) (interface{}, int, error) {
	var err error
	response, httpStatus, err := h.Get(url)
	if err != nil {
		return nil, httpStatus, err
	}

	slog.With("payload", string(*response)).Debug("JSON Response")

	err = json.Unmarshal(*response, target)
	if err != nil {
		return nil, httpStatus, err
	}

	return target, httpStatus, nil
}

func (h *HTTPClient) Get(url string) (*[]byte, int, error) {
	slog.With("client", "http", "method", "get", "url", url).Info("Performing request")
	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		slog.With("client", "http", "url", url, "error", err, "method", "GET").Error("Could not create new request")
		return nil, 500, err
	}

	for _, header := range h.Headers {
		req.Header.Set(header.key, header.value)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		slog.With("client", "http", "method", "GET", "url", url, "error", err).Error("Could not perform request")
		return nil, resp.StatusCode, err
	}

	defer resp.Body.Close() //nolint:errcheck // Ignore errors on close

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.With("client", "http", "url", url, "error", err).Error("Could not read body")
		return nil, resp.StatusCode, err
	}

	// log.With("client", "http", "url", url).Debug(string(body))

	return &body, resp.StatusCode, err
}

func NewClient() *HTTPClient {
	httpClient := HTTPClient{}
	slog.With("client", "http").Debug("new instance")
	return &httpClient
}
