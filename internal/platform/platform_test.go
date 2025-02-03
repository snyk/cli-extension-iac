package platform_test

import (
	"context"
	"testing"

	"github.com/snyk/cli-extension-iac/internal/cloudapi"
	"github.com/snyk/cli-extension-iac/internal/platform"
	engine "github.com/snyk/cli-extension-iac/internal/policyengine"
	"github.com/snyk/policy-engine/pkg/models"
	"github.com/stretchr/testify/require"
)

type mockCloudAPIClient struct {
	createScan func(ctx context.Context, orgID string, request *cloudapi.CreateScanRequest, useInternalEndpoint bool) (*cloudapi.CreateScanResponse, error)
}

func (c mockCloudAPIClient) CreateScan(ctx context.Context, orgID string, request *cloudapi.CreateScanRequest, useInternalEndpoint bool) (*cloudapi.CreateScanResponse, error) {
	return c.createScan(ctx, orgID, request, useInternalEndpoint)
}

func TestSnykPlatformForCli(t *testing.T) {
	resourcesStubbed := false
	isCreateScanCalled := false

	stubResources := func(results *engine.Results) *engine.Results {
		resourcesStubbed = true
		return nil
	}

	serializeEngineResults := func(results *engine.Results) (string, error) {
		return "test-serialized-results", nil
	}
	cloudAPIClient := mockCloudAPIClient{
		createScan: func(ctx context.Context, orgID string, request *cloudapi.CreateScanRequest, useInternalEndpoint bool) (*cloudapi.CreateScanResponse, error) {
			isCreateScanCalled = true
			require.False(t, useInternalEndpoint)
			require.Equal(t, cloudapi.CreateScanRequest{
				Data: cloudapi.Data{
					Attributes: cloudapi.Attributes{
						Kind:      "cli",
						Artifacts: "test-serialized-results",
						Options: cloudapi.AttributesOptions{
							Branch: "master",
						},
						EnvironmentMetadata: cloudapi.EnvironmentMetadata{
							Name: "owner/repo",
							Options: cloudapi.EnvironmentMetadataOptions{
								SourceType: "cli",
								SourceURI:  "https://github.com/owner/repo",
							},
						},
					},
					Type: "scan",
				},
			}, *request)
			return &cloudapi.CreateScanResponse{Data: cloudapi.CreateScanResponseData{ID: "scanId"}}, nil
		},
	}

	snykPlatform := platform.SnykPlatformClient{
		RestAPIURL:             "https://api.dev.snyk.io",
		CloudAPIClient:         cloudAPIClient,
		StubResources:          stubResources,
		SerializeEngineResults: serializeEngineResults,
	}

	results := engine.Results{
		Format:        "format",
		FormatVersion: "format-version",
		Results:       []models.Result{},
	}
	opts := platform.ShareResultsOptions{
		OrgPublicID: "orgId",
		Kind:        "cli",
		Name:        "owner/repo",
		Branch:      "master",
		SourceURI:   "https://github.com/owner/repo",
		SourceType:  "cli",
	}
	shareResultsOutput, err := snykPlatform.ShareResults(context.Background(), &results, opts)
	require.Equal(t,
		"https://api.dev.snyk.io/rest/orgs/orgId/cloud/scans/scanId?version=2022-12-21~beta",
		shareResultsOutput.URL,
	)

	require.NoError(t, err)
	require.True(t, isCreateScanCalled)
	require.True(t, resourcesStubbed)
}

func TestSnykPlatformForScm(t *testing.T) {
	resourcesStubbed := false
	isCreateScanCalled := false

	stubResources := func(results *engine.Results) *engine.Results {
		resourcesStubbed = true
		return nil
	}
	serializeEngineResults := func(results *engine.Results) (string, error) {
		return "test-serialized-results", nil
	}
	cloudAPIClient := mockCloudAPIClient{
		createScan: func(ctx context.Context, orgID string, request *cloudapi.CreateScanRequest, useInternalEndpoint bool) (*cloudapi.CreateScanResponse, error) {
			isCreateScanCalled = true
			require.True(t, useInternalEndpoint)
			require.Equal(t, cloudapi.CreateScanRequest{
				Data: cloudapi.Data{
					Attributes: cloudapi.Attributes{
						Kind:      "scm",
						Artifacts: "test-serialized-results",
						Options: cloudapi.AttributesOptions{
							Branch: "master",
						},
						EnvironmentMetadata: cloudapi.EnvironmentMetadata{
							Name:      "owner/repo",
							ProjectID: "project-id",
							Options: cloudapi.EnvironmentMetadataOptions{
								SourceType: "github",
								SourceURI:  "https://github.com/owner/repo",
							},
						},
					},
					Type: "scan",
				},
			}, *request)
			return &cloudapi.CreateScanResponse{Data: cloudapi.CreateScanResponseData{ID: "scanId"}}, nil
		},
	}

	snykPlatform := platform.SnykPlatformClient{
		CloudAPIClient:         cloudAPIClient,
		StubResources:          stubResources,
		SerializeEngineResults: serializeEngineResults,
	}

	results := engine.Results{
		Format:        "format",
		FormatVersion: "format-version",
		Results:       []models.Result{},
	}
	opts := platform.ShareResultsOptions{
		OrgPublicID: "orgId",
		Kind:        "scm",
		Name:        "owner/repo",
		Branch:      "master",
		SourceURI:   "https://github.com/owner/repo",
		SourceType:  "github",
		ProjectID:   "project-id",
	}
	_, err := snykPlatform.ShareResults(context.Background(), &results, opts)

	require.NoError(t, err)
	require.True(t, isCreateScanCalled)
	require.True(t, resourcesStubbed)
}

func TestSnykPlatformForTFC(t *testing.T) {
	resourcesStubbed := false
	isCreateScanCalled := false

	stubResources := func(results *engine.Results) *engine.Results {
		resourcesStubbed = true
		return nil
	}
	serializeEngineResults := func(results *engine.Results) (string, error) {
		return "test-serialized-results", nil
	}
	cloudAPIClient := mockCloudAPIClient{
		createScan: func(ctx context.Context, orgID string, request *cloudapi.CreateScanRequest, useInternalEndpoint bool) (*cloudapi.CreateScanResponse, error) {
			isCreateScanCalled = true
			require.True(t, useInternalEndpoint)
			require.Equal(t, cloudapi.CreateScanRequest{
				Data: cloudapi.Data{
					Attributes: cloudapi.Attributes{
						Kind:      "tfc",
						Artifacts: "test-serialized-results",
						Options: cloudapi.AttributesOptions{
							RunID: "1234567890",
						},
						EnvironmentMetadata: cloudapi.EnvironmentMetadata{
							Name: "owner/repo",
							Options: cloudapi.EnvironmentMetadataOptions{
								SourceType: "terraform-cloud",
								SourceURI:  "https://application.terraform.com/owner/repo",
							},
						},
					},
					Type: "scan",
				},
			}, *request)
			return &cloudapi.CreateScanResponse{Data: cloudapi.CreateScanResponseData{ID: "scanId"}}, nil
		},
	}

	snykPlatform := platform.SnykPlatformClient{
		CloudAPIClient:         cloudAPIClient,
		StubResources:          stubResources,
		SerializeEngineResults: serializeEngineResults,
	}

	results := engine.Results{
		Format:        "format",
		FormatVersion: "format-version",
		Results:       []models.Result{},
	}
	opts := platform.ShareResultsOptions{
		OrgPublicID: "orgId",
		Kind:        "tfc",
		Name:        "owner/repo",
		RunID:       "1234567890",
		SourceURI:   "https://application.terraform.com/owner/repo",
		SourceType:  "terraform-cloud",
	}
	_, err := snykPlatform.ShareResults(context.Background(), &results, opts)

	require.NoError(t, err)
	require.True(t, isCreateScanCalled)
	require.True(t, resourcesStubbed)
}
