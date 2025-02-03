package cloudapi

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/snyk/policy-engine/pkg/bundle"
)

const versionLegacyApi = "2022-12-21~beta"
const versionInternalApi = "2022-12-21~beta"
const version = "2024-09-24~beta"

func (c *ClientImpl) customRules(ctx context.Context, url string) (readers []bundle.Reader, e error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/octet-stream")

	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err := res.Body.Close(); err != nil && e == nil {
			e = err
		}
	}()

	if res.StatusCode == http.StatusForbidden {
		return nil, ErrForbidden
	}

	if res.StatusCode != http.StatusOK {
		if body, err := io.ReadAll(res.Body); err != nil {
			return nil, fmt.Errorf("invalid status code: %v", res.StatusCode)
		} else {
			return nil, fmt.Errorf("invalid status code: %d, response body: %s", res.StatusCode, string(body))
		}
	}

	var bundles []bundle.Reader
	tr := tar.NewReader(res.Body)
	for {
		header, err := tr.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		b, err := bundle.NewTarGzReader(header.Name, tr)
		if err != nil {
			return nil, err
		}
		bundles = append(bundles, b)
	}

	return bundles, nil
}

func (c *ClientImpl) CustomRules(ctx context.Context, orgID string) (readers []bundle.Reader, e error) {
	url := fmt.Sprintf("%s/hidden/orgs/%s/cloud/custom_rules?version=%s", c.url, orgID, versionLegacyApi)

	if c.iacNewEngine {
		url = fmt.Sprintf("%s/hidden/orgs/%s/cloud/rule_bundles?version=%s", c.url, orgID, version)
	}

	return c.customRules(ctx, url)
}

func (c *ClientImpl) CustomRulesInternal(ctx context.Context, orgID string) (readers []bundle.Reader, e error) {
	url := fmt.Sprintf("%s/internal/orgs/%s/cloud/custom_rules?version=%s", c.url, orgID, versionInternalApi)

	return c.customRules(ctx, url)
}
