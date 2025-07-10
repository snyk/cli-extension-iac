package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type TrackUsageData struct {
	IsPrivate       bool `json:"isPrivate"`
	IssuesPrevented int  `json:"issuesPrevented"`
}

type TrackUsageRequestBody struct {
	Results []TrackUsageData `json:"results"`
}

type TrackUsageError struct {
	TestLimitReached bool
	Err              error
}

type TrackUsageResponse struct {
	statusCode *int
	err        error
}

func (c *Client) TrackUsage(ctx context.Context, org string) (outputErr TrackUsageError) {
	trackUsageResponse := c.trackUsageRegistry(ctx, org)

	switch *trackUsageResponse.statusCode {
	case 200:
		return TrackUsageError{false, nil}
	case 429:
		return TrackUsageError{true, nil}
	default:
		if trackUsageResponse.err != nil {
			return TrackUsageError{false, trackUsageResponse.err}
		}
	}

	return TrackUsageError{false, nil}
}

func (c *Client) trackUsageRegistry(ctx context.Context, org string) (response TrackUsageResponse) {
	bodyData := []TrackUsageData{{true, 1}}
	bodyResults := TrackUsageRequestBody{bodyData}

	body, err := json.Marshal(bodyResults)
	if err != nil {
		return TrackUsageResponse{nil, fmt.Errorf("failed to marshal request body: %w", err)}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/v1/track-iac-usage/cli", c.url), bytes.NewBuffer(body))
	if err != nil {
		return TrackUsageResponse{nil, fmt.Errorf("create request: %v", err)}
	}

	query := req.URL.Query()
	query.Set("org", org)
	req.URL.RawQuery = query.Encode()

	req.Header.Set("Content-Type", "application/json")

	res, err := c.httpClient.Do(req)
	if err != nil {
		return TrackUsageResponse{nil, fmt.Errorf("perform request: %v", err)}
	}

	defer func() {
		if err := res.Body.Close(); err != nil && response.err == nil {
			response.err = fmt.Errorf("close response body: %v", err)
		}
	}()

	return TrackUsageResponse{&res.StatusCode, response.err}
}
