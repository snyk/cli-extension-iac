package cloudapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

type (
	CollectionDocumentRes struct {
		Data []ResourceObject `json:"data"`
	}

	ResourceObject struct {
		ID         string             `json:"id,omitempty"`
		Type       string             `json:"type"`
		Attributes ResourceAttributes `json:"attributes,omitempty"`
	}

	ResourceAttributes struct {
		State map[string]interface{}
	}
)

func (c *ClientImpl) Resources(ctx context.Context, orgID, environmentID, resourceType, resourceKind string) (resources []ResourceObject, e error) {

	url := fmt.Sprintf("%s/rest/orgs/%s/cloud/resources", c.url, orgID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	query := req.URL.Query()
	query.Set("environment_id", environmentID)
	query.Set("resource_type", resourceType)
	query.Set("kind", resourceKind)
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

	var results CollectionDocumentRes

	body, _ := io.ReadAll(res.Body)
	if err := json.Unmarshal(body, &results); err != nil {
		return nil, err
	}

	return results.Data, nil
}
