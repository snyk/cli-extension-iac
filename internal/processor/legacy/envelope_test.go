package legacy

import (
	"errors"
	"testing"

	"github.com/snyk/cli-extension-iac/internal/registry"
	"github.com/snyk/cli-extension-iac/internal/results"
	"github.com/stretchr/testify/require"
)

func TestConvertResultsToEnvelopeScanResult(t *testing.T) {
	type testInput struct {
		results     results.Results
		projectName string
		policy      string
	}

	tests := []struct {
		name      string
		processor ShareResults
		input     testInput
		output    registry.ScanResult
	}{
		{
			name: "with basic params set",
			processor: ShareResults{
				AllowAnalytics:  true,
				GetWd:           func() (string, error) { return "Project Name", errors.New("an error to fail `getTarget`") },
				TargetReference: "target-branch",
			},
			input: testInput{
				results: results.Results{
					Resources: []results.Resource{
						{
							ID:            "first-resource.id",
							Type:          "first-resource-type",
							Path:          []any{"attribute", "nested_attribute"},
							FormattedPath: "first-resource.resource[id].attribute.nested_attribute",
							Kind:          "terraformconfig",
							File:          "resource-file",
							Line:          41,
							Column:        42,
						},
						{
							ID:            "second-resource.id",
							Type:          "second-resource-type",
							Path:          []any{"attribute", "nested_attribute"},
							FormattedPath: "second-resource.resource[id].attribute.nested_attribute",
							Kind:          "terraformconfig",
							File:          "resource-file",
							Line:          41,
							Column:        42,
						},
						{
							ID:            "another-resource.id",
							Type:          "another-resource-type",
							Path:          []any{"attribute", "nested_attribute"},
							FormattedPath: "another-resource.resource[id].attribute.nested_attribute",
							Kind:          "terraformconfig",
							File:          "another-resource-file",
							Line:          41,
							Column:        42,
						},
					},
					Vulnerabilities: []results.Vulnerability{
						{
							Rule: results.Rule{
								ID:          "rule-id",
								Title:       "rule-title",
								Description: "rule-description",
								References:  "",
								Labels:      []string{},
								Category:    "rule-category",
							},
							Message:     "result-message",
							Remediation: "result-remediation",
							Severity:    "medium",
							Ignored:     true,
							Resource: results.Resource{
								ID:            "first-resource.id",
								Type:          "first-resource-type",
								Path:          []any{"attribute", "nested_attribute"},
								FormattedPath: "first-resource.resource[id].attribute.nested_attribute",
								File:          "resource-file",
								Kind:          "terraformconfig",
								Line:          1,
								Column:        2,
							},
						},
						{
							Rule: results.Rule{
								ID:          "rule-id",
								Title:       "rule-title",
								Description: "rule-description",
								References:  "",
								Labels:      []string{},
								Category:    "rule-category",
							},
							Message:     "result-message",
							Remediation: "result-remediation",
							Severity:    "medium",
							Ignored:     true,
							Resource: results.Resource{
								ID:            "second-resource.id",
								Type:          "second-resource-type",
								Path:          []any{"attribute", "nested_attribute"},
								FormattedPath: "second-resource.resource[id].attribute.nested_attribute",
								File:          "resource-file",
								Kind:          "terraformconfig",
								Line:          1,
								Column:        2,
							},
						},
						{
							Rule: results.Rule{
								ID:          "rule-id",
								Title:       "rule-title",
								Description: "rule-description",
								References:  "",
								Labels:      []string{},
								Category:    "rule-category",
							},
							Message:     "result-message",
							Remediation: "result-remediation",
							Severity:    "medium",
							Ignored:     true,
							Resource: results.Resource{
								ID:            "another-resource.id",
								Type:          "another-resource-type",
								Path:          []any{"attribute", "nested_attribute"},
								FormattedPath: "another-resource.resource[id].attribute.nested_attribute",
								File:          "another-resource-file",
								Kind:          "terraformconfig",
								Line:          2,
								Column:        2,
							},
						},
					},
				},
				projectName: "Project Name",
			},
			output: registry.ScanResult{
				Identity: registry.Identity{
					Type:       "iac",
					TargetFile: "Infrastructure_as_code_issues",
				},
				Facts:  []struct{}{},
				Name:   "Project Name",
				Policy: "",
				Findings: []registry.Finding{
					{
						Data: registry.Data{
							Metadata: registry.RuleMetadata{
								PublicID:                "rule-id",
								Title:                   "rule-title",
								Documentation:           "",
								IsGeneratedByCustomRule: false,
								Description:             "",
								Severity:                "medium",
								Issue:                   "rule-title",
								Impact:                  "rule-description",
								Resolve:                 "",
								References:              []string{},
							},
							IssueMetadata: registry.IssueMetadata{
								Type: "terraformconfig",
								File: "resource-file",
								ResourceInfo: registry.ResourceInfo{
									Type: "first-resource-type",
								},
								ResourcePath: "first-resource.resource[id].attribute.nested_attribute",
								LineNumber:   1,
							},
						},
						Type: "iacIssue",
					},
					{
						Data: registry.Data{
							Metadata: registry.RuleMetadata{
								PublicID:                "rule-id",
								Title:                   "rule-title",
								Documentation:           "",
								IsGeneratedByCustomRule: false,
								Description:             "",
								Severity:                "medium",
								Issue:                   "rule-title",
								Impact:                  "rule-description",
								Resolve:                 "",
								References:              []string{},
							},
							IssueMetadata: registry.IssueMetadata{
								Type: "terraformconfig",
								File: "resource-file",
								ResourceInfo: registry.ResourceInfo{
									Type: "second-resource-type",
								},
								ResourcePath: "second-resource.resource[id].attribute.nested_attribute",
								LineNumber:   1,
							},
						},
						Type: "iacIssue",
					},
					{
						Data: registry.Data{
							Metadata: registry.RuleMetadata{
								PublicID:                "rule-id",
								Title:                   "rule-title",
								Documentation:           "",
								IsGeneratedByCustomRule: false,
								Description:             "",
								Severity:                "medium",
								Issue:                   "rule-title",
								Impact:                  "rule-description",
								Resolve:                 "",
								References:              []string{},
							},
							IssueMetadata: registry.IssueMetadata{
								Type: "terraformconfig",
								File: "another-resource-file",
								ResourceInfo: registry.ResourceInfo{
									Type: "another-resource-type",
								},
								ResourcePath: "another-resource.resource[id].attribute.nested_attribute",
								LineNumber:   2,
							},
						},
						Type: "iacIssue",
					},
				},
				Target: registry.Target{
					Name: "Project Name",
				},
				TargetReference: "target-branch",
			},
		},
		{
			name: "with remote-repo-url set",
			processor: ShareResults{
				AllowAnalytics: true,
				GetWd:          func() (string, error) { return "Project Name", nil },
				RemoteRepoUrl:  "git@github.com:test/remote-repo-url.git",
			},
			input: testInput{
				results: results.Results{
					Resources: []results.Resource{
						{
							ID:            "first-resource.id",
							Type:          "first-resource-type",
							Path:          []any{"attribute", "nested_attribute"},
							FormattedPath: "first-resource.resource[id].attribute.nested_attribute",
							Kind:          "terraformconfig",
							File:          "resource-file",
							Line:          41,
							Column:        42,
						},
						{
							ID:            "second-resource.id",
							Type:          "second-resource-type",
							Path:          []any{"attribute", "nested_attribute"},
							FormattedPath: "second-resource.resource[id].attribute.nested_attribute",
							Kind:          "terraformconfig",
							File:          "resource-file",
							Line:          41,
							Column:        42,
						},
						{
							ID:            "another-resource.id",
							Type:          "another-resource-type",
							Path:          []any{"attribute", "nested_attribute"},
							FormattedPath: "another-resource.resource[id].attribute.nested_attribute",
							Kind:          "terraformconfig",
							File:          "another-resource-file",
							Line:          41,
							Column:        42,
						},
					},
					Vulnerabilities: []results.Vulnerability{
						{
							Rule: results.Rule{
								ID:          "rule-id",
								Title:       "rule-title",
								Description: "rule-description",
								References:  "",
								Labels:      []string{},
								Category:    "rule-category",
							},
							Message:     "result-message",
							Remediation: "result-remediation",
							Severity:    "medium",
							Ignored:     true,
							Resource: results.Resource{
								ID:            "first-resource.id",
								Type:          "first-resource-type",
								Path:          []any{"attribute", "nested_attribute"},
								FormattedPath: "first-resource.resource[id].attribute.nested_attribute",
								File:          "resource-file",
								Kind:          "terraformconfig",
								Line:          1,
								Column:        2,
							},
						},
						{
							Rule: results.Rule{
								ID:          "rule-id",
								Title:       "rule-title",
								Description: "rule-description",
								References:  "",
								Labels:      []string{},
								Category:    "rule-category",
							},
							Message:     "result-message",
							Remediation: "result-remediation",
							Severity:    "medium",
							Ignored:     true,
							Resource: results.Resource{
								ID:            "second-resource.id",
								Type:          "second-resource-type",
								Path:          []any{"attribute", "nested_attribute"},
								FormattedPath: "second-resource.resource[id].attribute.nested_attribute",
								File:          "resource-file",
								Kind:          "terraformconfig",
								Line:          1,
								Column:        2,
							},
						},
						{
							Rule: results.Rule{
								ID:          "rule-id",
								Title:       "rule-title",
								Description: "rule-description",
								References:  "",
								Labels:      []string{},
								Category:    "rule-category",
							},
							Message:     "result-message",
							Remediation: "result-remediation",
							Severity:    "medium",
							Ignored:     true,
							Resource: results.Resource{
								ID:            "another-resource.id",
								Type:          "another-resource-type",
								Path:          []any{"attribute", "nested_attribute"},
								FormattedPath: "another-resource.resource[id].attribute.nested_attribute",
								File:          "another-resource-file",
								Kind:          "terraformconfig",
								Line:          2,
								Column:        2,
							},
						},
					},
				},
				projectName: "Project Name",
			},
			output: registry.ScanResult{
				Identity: registry.Identity{
					Type:       "iac",
					TargetFile: "Infrastructure_as_code_issues",
				},
				Facts:  []struct{}{},
				Name:   "Project Name",
				Policy: "",
				Findings: []registry.Finding{
					{
						Data: registry.Data{
							Metadata: registry.RuleMetadata{
								PublicID:                "rule-id",
								Title:                   "rule-title",
								Documentation:           "",
								IsGeneratedByCustomRule: false,
								Description:             "",
								Severity:                "medium",
								Issue:                   "rule-title",
								Impact:                  "rule-description",
								Resolve:                 "",
								References:              []string{},
							},
							IssueMetadata: registry.IssueMetadata{
								Type: "terraformconfig",
								File: "resource-file",
								ResourceInfo: registry.ResourceInfo{
									Type: "first-resource-type",
								},
								ResourcePath: "first-resource.resource[id].attribute.nested_attribute",
								LineNumber:   1,
							},
						},
						Type: "iacIssue",
					},
					{
						Data: registry.Data{
							Metadata: registry.RuleMetadata{
								PublicID:                "rule-id",
								Title:                   "rule-title",
								Documentation:           "",
								IsGeneratedByCustomRule: false,
								Description:             "",
								Severity:                "medium",
								Issue:                   "rule-title",
								Impact:                  "rule-description",
								Resolve:                 "",
								References:              []string{},
							},
							IssueMetadata: registry.IssueMetadata{
								Type: "terraformconfig",
								File: "resource-file",
								ResourceInfo: registry.ResourceInfo{
									Type: "second-resource-type",
								},
								ResourcePath: "second-resource.resource[id].attribute.nested_attribute",
								LineNumber:   1,
							},
						},
						Type: "iacIssue",
					},
					{
						Data: registry.Data{
							Metadata: registry.RuleMetadata{
								PublicID:                "rule-id",
								Title:                   "rule-title",
								Documentation:           "",
								IsGeneratedByCustomRule: false,
								Description:             "",
								Severity:                "medium",
								Issue:                   "rule-title",
								Impact:                  "rule-description",
								Resolve:                 "",
								References:              []string{},
							},
							IssueMetadata: registry.IssueMetadata{
								Type: "terraformconfig",
								File: "another-resource-file",
								ResourceInfo: registry.ResourceInfo{
									Type: "another-resource-type",
								},
								ResourcePath: "another-resource.resource[id].attribute.nested_attribute",
								LineNumber:   2,
							},
						},
						Type: "iacIssue",
					},
				},
				Target: registry.Target{
					RemoteUrl: "http://github.com/test/remote-repo-url.git",
				},
			},
		},
		{
			name: "with snyk policy set",
			processor: ShareResults{
				AllowAnalytics: true,
				GetWd:          func() (string, error) { return "Project Name", errors.New("an error to fail `getTarget`") },
			},
			input: testInput{
				results: results.Results{
					Resources: []results.Resource{
						{
							ID:            "first-resource.id",
							Type:          "first-resource-type",
							Path:          []any{"attribute", "nested_attribute"},
							FormattedPath: "first-resource.resource[id].attribute.nested_attribute",
							Kind:          "terraformconfig",
							File:          "resource-file",
							Line:          41,
							Column:        42,
						},
						{
							ID:            "second-resource.id",
							Type:          "second-resource-type",
							Path:          []any{"attribute", "nested_attribute"},
							FormattedPath: "second-resource.resource[id].attribute.nested_attribute",
							Kind:          "terraformconfig",
							File:          "resource-file",
							Line:          41,
							Column:        42,
						},
						{
							ID:            "another-resource.id",
							Type:          "another-resource-type",
							Path:          []any{"attribute", "nested_attribute"},
							FormattedPath: "another-resource.resource[id].attribute.nested_attribute",
							Kind:          "terraformconfig",
							File:          "another-resource-file",
							Line:          41,
							Column:        42,
						},
					},
					Vulnerabilities: []results.Vulnerability{
						{
							Rule: results.Rule{
								ID:          "rule-id",
								Title:       "rule-title",
								Description: "rule-description",
								References:  "",
								Labels:      []string{},
								Category:    "rule-category",
							},
							Message:     "result-message",
							Remediation: "result-remediation",
							Severity:    "medium",
							Ignored:     true,
							Resource: results.Resource{
								ID:            "first-resource.id",
								Type:          "first-resource-type",
								Path:          []any{"attribute", "nested_attribute"},
								FormattedPath: "first-resource.resource[id].attribute.nested_attribute",
								File:          "resource-file",
								Kind:          "terraformconfig",
								Line:          1,
								Column:        2,
							},
						},
						{
							Rule: results.Rule{
								ID:          "rule-id",
								Title:       "rule-title",
								Description: "rule-description",
								References:  "",
								Labels:      []string{},
								Category:    "rule-category",
							},
							Message:     "result-message",
							Remediation: "result-remediation",
							Severity:    "medium",
							Ignored:     true,
							Resource: results.Resource{
								ID:            "second-resource.id",
								Type:          "second-resource-type",
								Path:          []any{"attribute", "nested_attribute"},
								FormattedPath: "second-resource.resource[id].attribute.nested_attribute",
								File:          "resource-file",
								Kind:          "terraformconfig",
								Line:          1,
								Column:        2,
							},
						},
						{
							Rule: results.Rule{
								ID:          "rule-id",
								Title:       "rule-title",
								Description: "rule-description",
								References:  "",
								Labels:      []string{},
								Category:    "rule-category",
							},
							Message:     "result-message",
							Remediation: "result-remediation",
							Severity:    "medium",
							Ignored:     true,
							Resource: results.Resource{
								ID:            "another-resource.id",
								Type:          "another-resource-type",
								Path:          []any{"attribute", "nested_attribute"},
								FormattedPath: "another-resource.resource[id].attribute.nested_attribute",
								File:          "another-resource-file",
								Kind:          "terraformconfig",
								Line:          2,
								Column:        2,
							},
						},
					},
				},
				projectName: "Project Name",
				policy:      "test-policy",
			},
			output: registry.ScanResult{
				Identity: registry.Identity{
					Type:       "iac",
					TargetFile: "Infrastructure_as_code_issues",
				},
				Facts:  []struct{}{},
				Name:   "Project Name",
				Policy: "test-policy",
				Findings: []registry.Finding{
					{
						Data: registry.Data{
							Metadata: registry.RuleMetadata{
								PublicID:                "rule-id",
								Title:                   "rule-title",
								Documentation:           "",
								IsGeneratedByCustomRule: false,
								Description:             "",
								Severity:                "medium",
								Issue:                   "rule-title",
								Impact:                  "rule-description",
								Resolve:                 "",
								References:              []string{},
							},
							IssueMetadata: registry.IssueMetadata{
								Type: "terraformconfig",
								File: "resource-file",
								ResourceInfo: registry.ResourceInfo{
									Type: "first-resource-type",
								},
								ResourcePath: "first-resource.resource[id].attribute.nested_attribute",
								LineNumber:   1,
							},
						},
						Type: "iacIssue",
					},
					{
						Data: registry.Data{
							Metadata: registry.RuleMetadata{
								PublicID:                "rule-id",
								Title:                   "rule-title",
								Documentation:           "",
								IsGeneratedByCustomRule: false,
								Description:             "",
								Severity:                "medium",
								Issue:                   "rule-title",
								Impact:                  "rule-description",
								Resolve:                 "",
								References:              []string{},
							},
							IssueMetadata: registry.IssueMetadata{
								Type: "terraformconfig",
								File: "resource-file",
								ResourceInfo: registry.ResourceInfo{
									Type: "second-resource-type",
								},
								ResourcePath: "second-resource.resource[id].attribute.nested_attribute",
								LineNumber:   1,
							},
						},
						Type: "iacIssue",
					},
					{
						Data: registry.Data{
							Metadata: registry.RuleMetadata{
								PublicID:                "rule-id",
								Title:                   "rule-title",
								Documentation:           "",
								IsGeneratedByCustomRule: false,
								Description:             "",
								Severity:                "medium",
								Issue:                   "rule-title",
								Impact:                  "rule-description",
								Resolve:                 "",
								References:              []string{},
							},
							IssueMetadata: registry.IssueMetadata{
								Type: "terraformconfig",
								File: "another-resource-file",
								ResourceInfo: registry.ResourceInfo{
									Type: "another-resource-type",
								},
								ResourcePath: "another-resource.resource[id].attribute.nested_attribute",
								LineNumber:   2,
							},
						},
						Type: "iacIssue",
					},
				},
				Target: registry.Target{
					Name: "Project Name",
				},
				TargetReference: "",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			expected := test.processor.convertResultsToEnvelopeScanResult(test.input.results, test.input.projectName, test.input.policy)
			require.Equal(t, test.output, expected)
		})
	}
}
