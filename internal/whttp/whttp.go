package whttp

// Wrapped HTTP client with prepared Get-Methods

import (
	"context"
	"encoding/json"
	"fmt"
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

// HTTP-Response with consumed body payload
type WHttpResponse struct {
	Header         http.Header
	HttpStatusCode int
	Body           []byte
}

func MakeHeader(key, value string) Header {
	return Header{
		key:   key,
		value: value,
	}
}

func (h *HTTPClient) get(url string) (WHttpResponse, error) {
	var err error

	slog.With("client", "http", "method", "get", "url", url).Info("Performing request")
	ctx := context.Background()
	var req *http.Request
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		slog.With("client", "http", "url", url, "error", err, "method", "GET").Error("Could not create new request")
		return WHttpResponse{Header: nil, HttpStatusCode: 500, Body: nil}, err
	}

	for _, header := range h.Headers {
		req.Header.Set(header.key, header.value)
	}

	var resp *http.Response
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		slog.With("client", "http", "method", "GET", "url", url, "error", err).Error("Could not perform request")
		return WHttpResponse{Header: nil, HttpStatusCode: resp.StatusCode, Body: nil}, err
	}

	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			slog.Error("error while closing response body",
				slog.Any("error", err),
				slog.String("url", url))
		}
	}()

	const limitInBytes = 30 * 1024 * 1024
	lrb := http.MaxBytesReader(nil, resp.Body, limitInBytes)
	var body []byte
	body, err = io.ReadAll(lrb)
	if err != nil {
		slog.With("client", "http", "url", url, "error", err).Error("Could not read body")
		return WHttpResponse{Header: resp.Header, HttpStatusCode: resp.StatusCode, Body: nil}, err
	}

	if resp.StatusCode >= 400 {
		err = fmt.Errorf("HTTP status code %d indicates error", resp.StatusCode)
	}

	return WHttpResponse{Header: resp.Header, HttpStatusCode: resp.StatusCode, Body: body}, err
}

func (h *HTTPClient) GetRaw(url string) ([]byte, int, error) {
	response, err := h.get(url)
	if err != nil {
		return nil, response.HttpStatusCode, err
	}

	return response.Body, response.HttpStatusCode, nil
}

func (h *HTTPClient) GetString(url string) (string, int, error) {
	response, err := h.get(url)
	if err != nil {
		return "", response.HttpStatusCode, err
	}

	return string(response.Body), response.HttpStatusCode, nil
}

func (h *HTTPClient) GetResponse(url string) (WHttpResponse, error) {
	return h.get(url)
}

func (h *HTTPClient) GetJSON(url string, target interface{}) (interface{}, WHttpResponse, error) {
	var err error
	response, err := h.get(url)
	if err != nil {
		return nil, response, err
	}

	slog.With("payload", string(response.Body)).Debug("JSON Response")

	err = json.Unmarshal(response.Body, target)
	if err != nil {
		return nil, response, err
	}

	return target, response, nil
}

func NewClient() *HTTPClient {
	httpClient := HTTPClient{}
	return &httpClient
}
