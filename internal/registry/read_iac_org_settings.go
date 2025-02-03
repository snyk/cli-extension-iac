package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

func (c *Client) ReadIACOrgSettings(ctx context.Context, request ReadIACOrgSettingsRequest) (_ *ReadIACOrgSettingsResponse, e error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/v1/iac-org-settings", c.url), nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %v", err)
	}

	query := req.URL.Query()
	query.Set("org", request.Org)
	req.URL.RawQuery = query.Encode()

	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("perform request: %v", err)
	}

	defer func() {
		if err := res.Body.Close(); err != nil && e == nil {
			e = fmt.Errorf("close response body: %v", err)
		}
	}()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("invalid status code: %v", res.StatusCode)
	}

	var response ReadIACOrgSettingsResponse

	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("decode response body: %v", err)
	}

	return &response, nil
}

type ReadIACOrgSettingsRequest struct {
	Org string
}

type ReadIACOrgSettingsResponse struct {
	CustomPolicies map[string]CustomPolicy `json:"customPolicies"`
	Entitlements   map[string]bool         `json:"entitlements"`
	Meta           Meta                    `json:"meta"`
}

type CustomPolicy struct {
	Severity string `json:"severity"`
}

type Meta struct {
	IgnoreSettings    IgnoreSettings `json:"ignoreSettings"`
	IsLicensesEnabled bool           `json:"isLicensesEnabled"`
	IsPrivate         bool           `json:"isPrivate"`
	Org               string         `json:"org"`
	OrgPublicId       string         `json:"orgPublicId"`
}

type IgnoreSettings struct {
	AdminOnly                  bool `json:"adminOnly"`
	DisregardFilesystemIgnores bool `json:"disregardFilesystemIgnores"`
	ReasonRequired             bool `json:"reasonRequired"`
}

type Entitlements struct {
	IacCustomRulesEntitlement bool `json:"iacCustomRulesEntitlement"`
	IacDrift                  bool `json:"iacDrift"`
	InfrastructureAsCode      bool `json:"infrastructureAsCode"`
}
