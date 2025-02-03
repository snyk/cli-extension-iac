package platform

import (
	"context"
	"fmt"
	"os"

	"github.com/snyk/cli-extension-iac/internal/cloudapi"
	"github.com/snyk/cli-extension-iac/internal/git"
	engine "github.com/snyk/cli-extension-iac/internal/policyengine"
	"github.com/snyk/cli-extension-iac/internal/processor/legacy"
	"github.com/snyk/cli-extension-iac/internal/registry"
	"github.com/snyk/cli-extension-iac/internal/results"
)

type SnykClient interface {
	CreateScan(ctx context.Context, orgID string, request *cloudapi.CreateScanRequest, useInternalEndpoint bool) (*cloudapi.CreateScanResponse, error)
}

type SnykPlatformClient struct {
	RestAPIURL             string
	CloudAPIClient         SnykClient
	RegistryClient         *registry.Client
	StubResources          func(results *engine.Results) *engine.Results
	SerializeEngineResults func(results *engine.Results) (string, error)
}

type ShareResultsOptions struct {
	OrgPublicID    string
	Kind           string
	Name           string
	Branch         string
	CommitSha      string
	RunID          string
	SourceURI      string
	SourceType     string
	ProjectID      string
	AllowAnalytics bool
}

type ShareResultsOutput struct {
	URL string
}

func (p *SnykPlatformClient) ShareResults(ctx context.Context, engineResults *engine.Results, opts ShareResultsOptions) (*ShareResultsOutput, error) {
	stubbedResults := p.StubResources(engineResults)

	artifacts, err := p.SerializeEngineResults(stubbedResults)
	if err != nil {
		return nil, fmt.Errorf("serialize engine results: %v", err)
	}

	request := cloudapi.CreateScanRequest{
		Data: cloudapi.Data{
			Type: "scan",
			Attributes: cloudapi.Attributes{
				Kind:      opts.Kind,
				Artifacts: artifacts,
				Options: cloudapi.AttributesOptions{
					Branch:    opts.Branch,
					CommitSha: opts.CommitSha,
					RunID:     opts.RunID,
				},
				EnvironmentMetadata: cloudapi.EnvironmentMetadata{
					Name:      opts.Name,
					ProjectID: opts.ProjectID,
					Options: cloudapi.EnvironmentMetadataOptions{
						SourceURI:  opts.SourceURI,
						SourceType: opts.SourceType,
					},
				},
			},
		},
	}

	useInternalEndpoint := false
	if opts.Kind != "cli" {
		useInternalEndpoint = true
	}

	response, err := p.CloudAPIClient.CreateScan(ctx, opts.OrgPublicID, &request, useInternalEndpoint)
	if err != nil {
		return nil, fmt.Errorf("Failed to store scan results: %v", err)
	}

	scanURL := fmt.Sprintf(
		"%s/rest/orgs/%s/cloud/scans/%s?version=%s",
		p.RestAPIURL,
		opts.OrgPublicID,
		response.Data.ID,
		"2022-12-21~beta",
	)

	return &ShareResultsOutput{URL: scanURL}, nil
}

func (p *SnykPlatformClient) ShareResultsRegistry(ctx context.Context, engineResults *results.Results, opts ShareResultsOptions, policy string) (*ShareResultsOutput, error) {
	shareResults := &legacy.ShareResults{
		RegistryClient: p.RegistryClient,
		AllowAnalytics: opts.AllowAnalytics,
		Policy:         policy,
		ProjectName:    opts.Name,
		RemoteRepoUrl:  opts.SourceURI,
		GetWd:          os.Getwd,
		GetRepoRootDir: git.GetRepoRootDir,
		GetOriginUrl:   git.GetOriginUrl,
	}

	err := shareResults.ShareResults(engineResults)
	return nil, err
}
