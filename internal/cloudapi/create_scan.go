package cloudapi

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	engine "github.com/snyk/cli-extension-iac/internal/policyengine"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

type CreateScanRequest struct {
	Data Data `json:"data"`
}

type Data struct {
	Attributes Attributes `json:"attributes"`
	Type       string     `json:"type"`
}

type Attributes struct {
	Kind                string              `json:"kind"`
	Artifacts           string              `json:"artifacts"`
	Options             AttributesOptions   `json:"options"`
	EnvironmentMetadata EnvironmentMetadata `json:"environment_metadata"`
}

type AttributesOptions struct {
	Branch    string `json:"branch,omitempty"`
	CommitSha string `json:"commit_sha,omitempty"`
	RunID     string `json:"run_id,omitempty"`
}

type EnvironmentMetadata struct {
	Name      string                     `json:"name"`
	ProjectID string                     `json:"project_id,omitempty"`
	Options   EnvironmentMetadataOptions `json:"options"`
}

type EnvironmentMetadataOptions struct {
	SourceURI  string `json:"source_uri"`
	SourceType string `json:"source_type"`
}

type CreateScanResponse struct {
	Data CreateScanResponseData `json:"data"`
}

type CreateScanResponseData struct {
	ID string `json:"id"`
}

func (c *ClientImpl) CreateScan(ctx context.Context, orgID string, request *CreateScanRequest, useInternalEndpoint bool) (_ *CreateScanResponse, e error) {
	var body bytes.Buffer

	if err := json.NewEncoder(&body).Encode(request); err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/hidden/orgs/%s/cloud/scans", c.url, orgID)
	if useInternalEndpoint {
		url = fmt.Sprintf("%s/internal/orgs/%s/cloud/scans", c.url, orgID)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &body)
	if err != nil {
		return nil, err
	}

	query := req.URL.Query()
	query.Set("version", c.version)
	req.URL.RawQuery = query.Encode()

	req.Header.Set("Content-Type", "application/vnd.api+json")

	res, err := c.httpClient.Do(req)
	if err != nil {
		var tmp snyk_errors.Error
		if ok := errors.As(err, &tmp); !ok {
			return nil, err
		}

		switch tmp.StatusCode {
		case http.StatusOK:
		default:
			return nil, fmt.Errorf("invalid status code: %d, details: %s", tmp.StatusCode, string(tmp.Detail))
		}
	}

	defer func() {
		if err := res.Body.Close(); err != nil && e == nil {
			e = err
		}
	}()

	responseBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("could not read response body: %w", err)
	}

	csr := CreateScanResponse{}
	if err := json.Unmarshal(responseBody, &csr); err != nil {
		return nil, fmt.Errorf("could not parse response: %w", err)
	}

	return &csr, nil
}

func SerializeEngineResults(results *engine.Results) (string, error) {
	var archive bytes.Buffer

	if err := compressEngineResults(&archive, results); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(archive.Bytes()), nil
}

func compressEngineResults(w io.Writer, results *engine.Results) error {
	archive := zip.NewWriter(w)

	file, err := archive.Create("output.json")
	if err != nil {
		return err
	}

	if err := json.NewEncoder(file).Encode(results); err != nil {
		return err
	}

	if err := archive.Close(); err != nil {
		return err
	}

	return nil
}
