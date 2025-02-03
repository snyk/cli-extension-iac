package cloudapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/snyk/policy-engine/pkg/bundle"
)

var (
	ErrForbidden = errors.New("forbidden")
)

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type ClientConfig struct {
	HTTPClient   HTTPClient
	URL          string
	Version      string
	IacNewEngine bool
}

type Client interface {
	CustomRules(ctx context.Context, orgID string) (readers []bundle.Reader, e error)
	CustomRulesInternal(ctx context.Context, orgID string) (readers []bundle.Reader, e error)
	CreateScan(ctx context.Context, orgID string, request *CreateScanRequest, useInternalEndpoint bool) (csr *CreateScanResponse, e error)
	Environments(ctx context.Context, orgID, snykCloudEnvironmentID string) (envs []EnvironmentObject, e error)
	Resources(ctx context.Context, orgID, environmentID, resourceType, resourceKind string) (resources []ResourceObject, e error)
}

type ClientImpl struct {
	httpClient   HTTPClient
	url          string
	version      string
	iacNewEngine bool
}

func NewClient(config ClientConfig) *ClientImpl {
	return &ClientImpl{
		httpClient:   config.HTTPClient,
		url:          config.URL,
		version:      config.Version,
		iacNewEngine: config.IacNewEngine,
	}
}
