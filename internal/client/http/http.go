package http

import (
	"io"
	"log/slog"
	"net/http"
)

type Header struct {
	key   string
	value string
}

type HttpClient struct {
	Token   string
	Headers []Header
}

func MakeHeader(key string, value string) Header {
	return Header{key: key, value: value}
}

func (h *HttpClient) Get(url string) (*[]byte, error) {
	slog.With("client", "http", "method", "get", "url", url).Info("Performing request")
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		slog.With("client", "http", "url", url, "error", err, "method", "GET").Error("Could not create new request")
		panic(err)
	}

	for _, header := range h.Headers {
		req.Header.Set(header.key, header.value)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		slog.With("client", "http", "method", "GET", "url", url, "error", err).Error("Could not perform request")
		return nil, err
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.With("client", "http", "url", url, "error", err).Error("Could not read body")
		return nil, err
	}

	//log.With("client", "http", "url", url).Debug(string(body))

	return &body, err
}

func NewClient() *HttpClient {
	httpClient := HttpClient{}
	slog.With("client", "http").Debug("new instance")
	return &httpClient
}
