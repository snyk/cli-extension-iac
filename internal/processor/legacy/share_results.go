package legacy

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/snyk/cli-extension-iac/internal/git"
	"github.com/snyk/cli-extension-iac/internal/registry"
	"github.com/snyk/cli-extension-iac/internal/results"
)

type RegistryClient interface {
	ShareResults(req registry.ShareResultsRequest) (registry.ShareResultsResponse, error)
}

type ShareResults struct {
	RegistryClient             RegistryClient
	Report                     bool
	AllowAnalytics             bool
	Policy                     string
	ProjectName                string
	ProjectBusinessCriticality *string
	ProjectEnvironment         *string
	ProjectLifecycle           *string
	ProjectTags                *string
	TargetReference            string
	RemoteRepoUrl              string
	GetWd                      func() (string, error)
	GetRepoRootDir             func(string) (string, error)
	GetOriginUrl               func(string) (string, error)
}

func (p *ShareResults) ShareResults(scanResults *results.Results) error {
	contributors, err := p.listContributors()
	if err != nil {
		return fmt.Errorf("list contributors: %v", err)
	}

	attributes := registry.Attributes{
		Criticality: stringPtrToStringSlicePtr(p.ProjectBusinessCriticality),
		Environment: stringPtrToStringSlicePtr(p.ProjectEnvironment),
		Lifecycle:   stringPtrToStringSlicePtr(p.ProjectLifecycle),
	}

	tags := p.formatTags()

	shareResultsRequest := registry.ShareResultsRequest{
		// there is only one ScanResult, but we send an array for backwards compatibility
		ScanResults:  []registry.ScanResult{p.convertResultsToEnvelopeScanResult(*scanResults, p.ProjectName, p.Policy)},
		Contributors: contributors,
		Attributes:   &attributes,
	}

	if len(tags) != 0 {
		shareResultsRequest.Tags = &tags
	}

	if _, err := p.RegistryClient.ShareResults(shareResultsRequest); err != nil {
		return fmt.Errorf("share results: %v", err)
	}

	return nil
}

func (p *ShareResults) formatTags() []registry.Tag {
	pairs := stringPtrToStringSlicePtr(p.ProjectTags)

	if pairs == nil {
		return []registry.Tag{}
	}

	if len(*pairs) == 0 {
		return []registry.Tag{}
	}

	var tags []registry.Tag

	for _, pair := range *pairs {
		parts := strings.Split(pair, "=")

		tags = append(tags, registry.Tag{
			Key:   parts[0],
			Value: parts[1],
		})
	}

	return tags
}

func (p *ShareResults) listContributors() ([]git.Contributor, error) {
	if !p.AllowAnalytics {
		return nil, nil
	}

	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("read current working directory: %v", err)
	}

	contributors, err := git.ListContributors(cwd, time.Now().Add(-90*24*time.Hour), time.Now(), 500)
	if err != nil {
		return nil, fmt.Errorf("list contributors: %v", err)
	}

	return contributors, nil
}
