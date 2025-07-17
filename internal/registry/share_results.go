package registry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/snyk/cli-extension-iac/internal/git"
	"net/http"
)

func (c *Client) ShareResults(req ShareResultsRequest) (ShareResultsResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal scanResult: %v", err)
	}

	request, err := http.NewRequest("POST", c.url+"/v1/iac-cli-share-results", bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create validRequest: %v", err)
	}

	request.Header.Add("Content-Type", "application/json")

	query := request.URL.Query()
	query.Add("org", req.Org)
	request.URL.RawQuery = query.Encode()

	res, err := c.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("failed to send validRequest: %v", err)
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case 200:
		var response ShareResultsResponse
		if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
			return nil, fmt.Errorf("unable to decode response body: %v", err)
		}
		return response, nil
	case 400, 401, 403, 404, 429, 500:
		var errorResponse Error
		if err := json.NewDecoder(res.Body).Decode(&errorResponse); err != nil {
			return nil, fmt.Errorf("unable to decode response body: %v", err)
		}

		if errorResponse.StatusCode == 0 {
			errorResponse.StatusCode = res.StatusCode
		}
		return nil, &errorResponse
	default:
		return nil, fmt.Errorf("unexpected status code from the API %d", res.StatusCode)
	}
}

type Error struct {
	Code       int    `json:"code,omitempty"`
	Failure    string `json:"error,omitempty"`
	Message    string `json:"message,omitempty"`
	StatusCode int
}

func (err *Error) Error() string {
	return fmt.Sprintf("(%d) Share Results API error: %s", err.Code, err.Message)
}

type ShareResultsRequest struct {
	ScanResults  []ScanResult      `json:"scanResults"`
	Contributors []git.Contributor `json:"contributors,omitempty"`
	Tags         *[]Tag            `json:"tags,omitempty"`
	Attributes   *Attributes       `json:"attributes,omitempty"`
	Policy       string            `json:"policy,omitempty"`
	Org          string            `json:"-"`
}

type ShareResultsResponse map[string]string

type ScanResult struct {
	Identity        Identity   `json:"identity"`
	Facts           []struct{} `json:"facts"`
	Name            string     `json:"name"`
	Policy          string     `json:"policy"`
	Findings        []Finding  `json:"findings"`
	Target          Target     `json:"target"`
	TargetReference string     `json:"targetReference,omitempty"`
}

type Identity struct {
	Type       string `json:"type"`
	TargetFile string `json:"targetFile"`
}

type Target struct {
	RemoteUrl string `json:"remoteUrl,omitempty"`
	Branch    string `json:"branch,omitempty"`
	Name      string `json:"name,omitempty"`
}

type ResourceInfo struct {
	Type string            `json:"type,omitempty"`
	Tags map[string]string `json:"tags,omitempty"`
}

type Location struct {
	File         string `json:"file"`
	LineNumber   int    `json:"lineNumber"`
	ColumnNumber int    `json:"columnNumber"`
}

type IssueMetadata struct {
	PublicId       string       `json:"publicId"`
	Type           string       `json:"type,omitempty"`
	File           string       `json:"file"`
	ResourcePath   string       `json:"resourcePath"`
	ResourceInfo   ResourceInfo `json:"resourceInfo,omitempty"`
	LineNumber     int          `json:"lineNumber"`
	ColumnNumber   int          `json:"columnNumber"`
	SourceLocation []Location   `json:"sourceLocation,omitempty"`
}

type Finding struct {
	Data Data   `json:"data"`
	Type string `json:"type"`
}

type Data struct {
	Metadata      RuleMetadata  `json:"metadata"`
	IssueMetadata IssueMetadata `json:"issueMetadata"`
}

type RuleMetadata struct {
	PublicID      string   `json:"publicId"`
	Title         string   `json:"title"`
	Documentation string   `json:"documentation,omitempty"`
	IsCustomRule  bool     `json:"isCustomRule,omitempty"`
	Description   string   `json:"description,omitempty"`
	Severity      Severity `json:"severity"`
	Resolve       string   `json:"resolve"`
	Controls      []string `json:"controls,omitempty"`
}

type Tag struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type Attributes struct {
	Criticality *[]string `json:"criticality,omitempty"`
	Environment *[]string `json:"environment,omitempty"`
	Lifecycle   *[]string `json:"lifecycle,omitempty"`
}

type Severity string

type TargetFile string

type ProjectId string
