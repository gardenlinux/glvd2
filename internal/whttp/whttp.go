package whttp

// Wrapped HTTP client with prepared Get-Methods

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/gardenlinux/glvd2/internal/logging"
)

const (
	HTTPInternalServerError int = 500
	HTTPClientError         int = 400
)

var (
	linkHeaderRegexp = regexp.MustCompile(`<([^>]+)>;\s*rel="([^"]+)"`)
)

type Header struct {
	key   string
	value string
}

type HTTPClient struct {
	Token   string
	Headers []Header
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

func MakeHeader(key, value string) Header {
	return Header{
		key:   key,
		value: value,
	}
}

func (h *HTTPClient) get(url string) (Response, error) {
	var err error

	slog.With("client", "http", "method", "get", "url", url).Info("Performing request")
	ctx := context.Background()
	var req *http.Request
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		slog.With("client", "http", "url", url, "error", err, "method", "GET").Error("Could not create new request")
		return Response{Header: nil, HTTPStatusCode: HTTPInternalServerError, Body: nil}, err
	}

	for _, header := range h.Headers {
		req.Header.Set(header.key, header.value)
	}

	var resp *http.Response
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		slog.Error("could not perform request", slog.String("client", "http"), slog.String("method", "GET"), slog.String("url", url), slog.Any("error", err))
		return Response{Header: nil, HTTPStatusCode: resp.StatusCode, Body: nil, LinkHeader: LinkHeader{}}, err
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
		return Response{Header: resp.Header, HTTPStatusCode: resp.StatusCode, Body: nil}, err
	}

	if resp.StatusCode >= HTTPClientError {
		err = fmt.Errorf("HTTP status code %d indicates error", resp.StatusCode)
	}

	linkHeader := ParseLink(resp)
	return Response{Header: resp.Header, HTTPStatusCode: resp.StatusCode, Body: body, LinkHeader: linkHeader}, err
}

func (h *HTTPClient) GetRaw(url string) ([]byte, int, error) {
	response, err := h.get(url)
	if err != nil {
		return nil, response.HTTPStatusCode, err
	}

	return response.Body, response.HTTPStatusCode, nil
}

func (h *HTTPClient) GetString(url string) (string, int, error) {
	response, err := h.get(url)
	if err != nil {
		return "", response.HTTPStatusCode, err
	}

	return string(response.Body), response.HTTPStatusCode, nil
}

func (h *HTTPClient) GetResponse(url string) (Response, error) {
	return h.get(url)
}

func (h *HTTPClient) GetJSON(url string, target any) (any, Response, error) {
	var err error
	response, err := h.get(url)
	if err != nil {
		return nil, response, err
	}

	slog.Log(context.Background(), logging.LevelTrace, "payload", "url", url, "body", string(response.Body))

	err = json.Unmarshal(response.Body, target)
	if err != nil {
		return nil, response, err
	}

	return target, response, nil
}

func ParseLink(response *http.Response) LinkHeader {
	var result LinkHeader

	linkStr := response.Header.Get("link")
	for item := range strings.SplitSeq(linkStr, ",") {
		// now having: <https://api.github.com/organizations/61944014/repos?type=public&page=1&per_page=100>; rel=\"first\"
		item = strings.TrimSpace(item)
		matches := linkHeaderRegexp.FindStringSubmatch(item)
		if len(matches) > 2 {
			//slog.Debug("Matches", slog.String("1", matches[1]), slog.String("2", matches[2]))
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
				slog.Error("unknown link relation", "item", item)
			}
		}
	}
	return result
}

func NewClient() *HTTPClient {
	httpClient := HTTPClient{}
	return &httpClient
}
