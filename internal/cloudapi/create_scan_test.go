package cloudapi_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snyk/cli-extension-iac/internal/cloudapi"
	engine "github.com/snyk/cli-extension-iac/internal/policyengine"

	"github.com/snyk/policy-engine/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestCreateScan(t *testing.T) {
	response := &cloudapi.CreateScanResponse{cloudapi.CreateScanResponseData{ID: "test-scan"}}
	tests := []struct {
		name                string
		useInternalEndpoint bool
		expectedPath        string
	}{
		{
			name:                "using external endpoint",
			useInternalEndpoint: false,
			expectedPath:        "/hidden/orgs/org-id/cloud/scans",
		},
		{
			name:                "using internal endpoint",
			useInternalEndpoint: true,
			expectedPath:        "/internal/orgs/org-id/cloud/scans",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, tt.expectedPath, r.URL.Path)
				require.Equal(t, http.MethodPost, r.Method)
				require.Equal(t, "1.2.3", r.URL.Query().Get("version"))
				require.Equal(t, "application/vnd.api+json", r.Header.Get("Content-Type"))
				body, err := json.Marshal(response)
				require.NoError(t, err)
				_, err = w.Write(body)
				require.NoError(t, err)
			}))

			defer server.Close()

			client := cloudapi.NewClient(cloudapi.ClientConfig{
				HTTPClient: server.Client(),
				URL:        server.URL,
				Version:    "1.2.3",
			})

			_, err := client.CreateScan(context.Background(), "org-id", nil, tt.useInternalEndpoint)
			require.NoError(t, err)
		})
	}
}

func TestSerializeEngineResults(t *testing.T) {
	input := engine.Results{
		Format:        "format",
		FormatVersion: "format-version",
		Results:       []models.Result{},
	}

	serialized, err := cloudapi.SerializeEngineResults(&input)
	require.NoError(t, err)

	archiveData, err := base64.StdEncoding.DecodeString(serialized)
	require.NoError(t, err)

	archive, err := zip.NewReader(bytes.NewReader(archiveData), int64(len(archiveData)))
	require.NoError(t, err)

	file, err := archive.Open("output.json")
	require.NoError(t, err)

	defer func() {
		require.NoError(t, file.Close())
	}()

	fileData, err := io.ReadAll(file)
	require.NoError(t, err)

	var output engine.Results

	require.NoError(t, json.Unmarshal(fileData, &output))

	require.Equal(t, input, output)
}
