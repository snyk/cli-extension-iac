package registry

import (
	"net/http"
)

type ClientConfig struct {
	HTTPClient HTTPClient
	URL        string
}

type Client struct {
	httpClient HTTPClient
	url        string
}

func NewClient(config ClientConfig) *Client {
	return &Client{
		httpClient: config.HTTPClient,
		url:        config.URL,
	}
}

type HTTPClient interface {
	Do(r *http.Request) (*http.Response, error)
}
