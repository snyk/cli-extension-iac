package cloudapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type (
	CollectionDocumentEnvs struct {
		Data []EnvironmentObject `json:"data"`
	}

	EnvironmentAttributes struct {
		Name       string          `json:"name"`
		Options    json.RawMessage `json:"options,omitempty"`
		NativeID   string          `json:"native_id"`
		Properties json.RawMessage `json:"properties,omitempty"`
		Kind       string          `json:"kind"`
		Revision   int             `json:"revision"`
		CreatedAt  string          `json:"created_at"`
		Status     string          `json:"status"`
		Error      string          `json:"error,omitempty"`
		UpdatedAt  string          `json:"updated_at,omitempty"`
		UpdatedBy  string          `json:"updated_by,omitempty"`
	}

	EnvironmentObject struct {
		ID         string                 `json:"id,omitempty"`
		Type       string                 `json:"type"`
		Attributes *EnvironmentAttributes `json:"attributes,omitempty"`
	}
)

func (c *ClientImpl) Environments(ctx context.Context, orgID, snykCloudEnvironmentID string) (envs []EnvironmentObject, e error) {

	url := fmt.Sprintf("%s/rest/orgs/%s/cloud/environments", c.url, orgID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	query := req.URL.Query()
	query.Set("id", snykCloudEnvironmentID)
	query.Set("version", c.version)
	req.URL.RawQuery = query.Encode()

	req.Header.Set("Content-Type", "application/vnd.api+json")

	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err := res.Body.Close(); err != nil && e == nil {
			e = err
		}
	}()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("invalid status code: %v", res.StatusCode)
	}

	var results CollectionDocumentEnvs

	body, _ := io.ReadAll(res.Body)
	if err := json.Unmarshal(body, &results); err != nil {
		return nil, err
	}

	return results.Data, nil
}
