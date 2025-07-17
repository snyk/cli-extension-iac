package legacy

import (
	"github.com/pkg/errors"
	"github.com/snyk/iac-service/pkg/iacissue"
	"strings"

	"github.com/snyk/cli-extension-iac/internal/registry"
	"github.com/snyk/cli-extension-iac/internal/results"
)

func (p *ShareResults) convertResultsToEnvelopeScanResult(results results.Results, projectName string, policy string) (registry.ScanResult, error) {
	target := p.getTarget(projectName)

	findings := []registry.Finding{}
	for _, vulnerability := range results.Vulnerabilities {
		finding := convertVulnerabilityToFinding(vulnerability)
		publicId, err := iacissue.GenerateIacIssuePublicId(target.RemoteUrl,
			finding.Data.Metadata.PublicID,
			finding.Data.IssueMetadata.File,
			finding.Data.IssueMetadata.ResourcePath)
		if err != nil {
			return registry.ScanResult{}, errors.Wrap(err, "Failed to generate IAC issue public id for finding")
		}
		finding.Data.IssueMetadata.PublicId = publicId
		findings = append(findings, finding)
	}

	return registry.ScanResult{
		Identity: registry.Identity{
			Type:       "iac",
			TargetFile: "Infrastructure_as_code_issues",
		},
		Facts:           []struct{}{},
		Name:            projectName,
		Policy:          policy,
		Findings:        findings,
		Target:          target,
		TargetReference: p.TargetReference,
	}, nil
}

func (p *ShareResults) getTarget(projectName string) registry.Target {
	gitOriginUrl := p.RemoteRepoUrl
	if p.RemoteRepoUrl == "" {
		cwd, err := p.GetWd()
		if err != nil {
			return registry.Target{
				Name: projectName,
			}
		}

		url, err := p.GetOriginUrl(cwd)
		if err != nil {
			return registry.Target{
				Name: projectName,
			}
		}
		gitOriginUrl = url
	}

	formattedOriginUrl, err := formatOriginUrl(gitOriginUrl)
	if err != nil {
		return registry.Target{
			Name: projectName,
		}
	}

	return registry.Target{
		RemoteUrl: formattedOriginUrl,
		Name:      projectName,
	}
}

func convertVulnerabilityToFinding(vulnerability results.Vulnerability) registry.Finding {
	finding := registry.Finding{
		Data: registry.Data{
			Metadata: registry.RuleMetadata{
				PublicID:     vulnerability.Rule.ID,
				Title:        vulnerability.Rule.Title,
				Severity:     registry.Severity(vulnerability.Severity),
				Description:  vulnerability.Rule.Description,
				IsCustomRule: vulnerability.Rule.IsGeneratedByCustomRule,
			},
			IssueMetadata: registry.IssueMetadata{
				Type: vulnerability.Resource.Kind,
				File: vulnerability.Resource.File,
				ResourceInfo: registry.ResourceInfo{
					Type: vulnerability.Resource.Type,
					Tags: vulnerability.Resource.Tags,
				},
				ResourcePath: vulnerability.Resource.FormattedPath,
				LineNumber:   vulnerability.Resource.Line,
				ColumnNumber: vulnerability.Resource.Column,
			},
		},
		Type: "iacIssue",
	}

	// custom rules need additional metadata (that for standard rules is obtained through API)
	if vulnerability.Rule.IsGeneratedByCustomRule {
		finding.Data.Metadata.Resolve = vulnerability.Remediation
		// other metadata fields could be added too if needed for UI filtering: category, labels
		finding.Data.Metadata.Controls = vulnerability.Rule.Controls
	}

	// add location trace for the resource
	var locations []registry.Location
	for _, l := range vulnerability.Resource.SourceLocation {
		locations = append(locations, registry.Location{
			LineNumber:   l.Line,
			ColumnNumber: l.Column,
			File:         l.File,
		})
	}
	finding.Data.IssueMetadata.SourceLocation = locations

	return finding
}

func stringPtrToStringSlicePtr(v *string) *[]string {
	if v == nil {
		return nil
	}
	if *v == "" {
		return pointer([]string{})
	}
	return pointer(strings.Split(*v, ","))
}

func pointer[T any](v T) *T {
	return &v
}
