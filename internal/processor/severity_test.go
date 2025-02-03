package processor

import (
	"testing"

	"github.com/snyk/cli-extension-iac/internal/engine"
	"github.com/snyk/cli-extension-iac/internal/results"
	"github.com/snyk/policy-engine/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestApplySeverityThreshold(t *testing.T) {
	type TestInput struct {
		results           *results.Results
		severityThreshold string
	}

	tests := []struct {
		name   string
		input  TestInput
		output *results.Results
	}{
		{
			name: "unfiltered results",
			input: TestInput{
				results: &results.Results{
					Resources: []results.Resource{
						{
							ID:     "resource.id",
							Type:   "resource-type",
							Kind:   "terraformconfig",
							File:   "resource-file",
							Line:   41,
							Column: 42,
						},
					},
					Vulnerabilities: []results.Vulnerability{
						{
							Rule: results.Rule{
								ID:          "rule-id",
								Title:       "rule-title",
								Description: "rule-description",
							},
							Message:     "result-message",
							Remediation: "result-remediation",
							Severity:    "medium",
							Ignored:     true,
							Resource: results.Resource{
								ID:            "resource.id",
								Type:          "resource-type",
								Path:          []any{"attribute", "nested_attribute"},
								FormattedPath: "resource.resource[id].attribute.nested_attribute",
								File:          "resource-file",
								Kind:          "terraformconfig",
								Line:          1,
								Column:        2,
							},
						},
					},
				},
				severityThreshold: "medium",
			},
			output: &results.Results{
				Resources: []results.Resource{
					{
						ID:     "resource.id",
						Type:   "resource-type",
						Kind:   "terraformconfig",
						File:   "resource-file",
						Line:   41,
						Column: 42,
					},
				},
				Vulnerabilities: []results.Vulnerability{
					{
						Rule: results.Rule{
							ID:          "rule-id",
							Title:       "rule-title",
							Description: "rule-description",
						},
						Message:     "result-message",
						Remediation: "result-remediation",
						Severity:    "medium",
						Ignored:     true,
						Resource: results.Resource{
							ID:            "resource.id",
							Type:          "resource-type",
							Path:          []any{"attribute", "nested_attribute"},
							FormattedPath: "resource.resource[id].attribute.nested_attribute",
							File:          "resource-file",
							Kind:          "terraformconfig",
							Line:          1,
							Column:        2,
						},
					},
				},
			},
		},
		{
			name: "filtered results",
			input: TestInput{
				results: &results.Results{
					Resources: []results.Resource{
						{
							ID:     "resource.id",
							Type:   "resource-type",
							Kind:   "terraformconfig",
							File:   "resource-file",
							Line:   41,
							Column: 42,
						},
					},
					Vulnerabilities: []results.Vulnerability{
						{
							Rule: results.Rule{
								ID:          "rule-id",
								Title:       "rule-title",
								Description: "rule-description",
							},
							Message:     "result-message",
							Remediation: "result-remediation",
							Severity:    "medium",
							Ignored:     true,
							Resource: results.Resource{
								ID:            "resource.if",
								Type:          "resource-type",
								Path:          []any{"attribute", "nested_attribute"},
								FormattedPath: "resource.resource[id].attribute.nested_attribute",
								File:          "resource-file",
								Kind:          "terraformconfig",
								Line:          1,
								Column:        2,
							},
						},
					},
				},
				severityThreshold: "high",
			},
			output: &results.Results{
				Resources: []results.Resource{
					{
						ID:     "resource.id",
						Type:   "resource-type",
						Kind:   "terraformconfig",
						File:   "resource-file",
						Line:   41,
						Column: 42,
					},
				},
				Vulnerabilities: nil,
			},
		},
		{
			name: "results with invalid severities are filtered",
			input: TestInput{
				results: &results.Results{
					Resources: []results.Resource{
						{
							ID:     "resource.id",
							Type:   "resource-type",
							Kind:   "terraformconfig",
							File:   "resource-file",
							Line:   41,
							Column: 42,
						},
					},
					Vulnerabilities: []results.Vulnerability{
						{
							Rule: results.Rule{
								ID:          "rule-id",
								Title:       "rule-title",
								Description: "rule-description",
							},
							Message:     "result-message",
							Remediation: "result-remediation",
							Severity:    "wrong",
							Ignored:     true,
							Resource: results.Resource{
								ID:            "resource.id",
								Type:          "resource-type",
								Path:          []any{"attribute", "nested_attribute"},
								FormattedPath: "resource.resource[id].attribute.nested_attribute",
								File:          "resource-file",
								Kind:          "terraformconfig",
								Line:          1,
								Column:        2,
							},
						},
					},
				},
				severityThreshold: "medium",
			},
			output: &results.Results{
				Resources: []results.Resource{
					{
						ID:     "resource.id",
						Type:   "resource-type",
						Kind:   "terraformconfig",
						File:   "resource-file",
						Line:   41,
						Column: 42,
					},
				},
				Vulnerabilities: nil,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.output, filterBySeverityThreshold(test.input.results, test.input.severityThreshold))
		})
	}
}

func TestApplyCustomSeveritiesRawResults(t *testing.T) {
	tests := []struct {
		name   string
		input  *engine.Results
		output *engine.Results
	}{
		{
			name: "returns original results when there is no match for custom severities",
			input: &engine.Results{
				Format:        "",
				FormatVersion: "",
				Results: []models.Result{
					{
						Input: models.State{},
						RuleResults: []models.RuleResults{
							{
								Id: "SNYK-CC-TF-555",
								Results: []models.RuleResult{
									{
										Severity: "low",
									},
								},
							},
						},
					},
				},
			},
			output: &engine.Results{
				Format:        "",
				FormatVersion: "",
				Results: []models.Result{
					{
						Input: models.State{},
						RuleResults: []models.RuleResults{
							{
								Id: "SNYK-CC-TF-555",
								Results: []models.RuleResult{
									{
										Severity: "low",
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "overrides result with the custom severity",
			input: &engine.Results{
				Format:        "",
				FormatVersion: "",
				Results: []models.Result{
					{
						Input: models.State{},
						RuleResults: []models.RuleResults{
							{
								Id: "SNYK-CC-TF-5",
								Results: []models.RuleResult{
									{
										Severity: "high",
									},
								},
							},
						},
					},
				},
			},
			output: &engine.Results{
				Format:        "",
				FormatVersion: "",
				Results: []models.Result{
					{
						Input: models.State{},
						RuleResults: []models.RuleResults{
							{
								Id: "SNYK-CC-TF-5",
								Results: []models.RuleResult{
									{
										Severity: "low",
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "removes result that match none severity",
			input: &engine.Results{
				Format:        "",
				FormatVersion: "",
				Results: []models.Result{
					{
						Input: models.State{},
						RuleResults: []models.RuleResults{
							{
								Id: "SNYK-CC-GCP-100",
								Results: []models.RuleResult{
									{
										Severity: "high",
									},
								},
							},
						},
					},
				},
			},
			output: &engine.Results{
				Format:        "",
				FormatVersion: "",
				Results: []models.Result{
					{
						Input:       models.State{},
						RuleResults: []models.RuleResults{},
					},
				},
			},
		},
		{
			name: "updates & removes issues with the relevant custom severities",
			input: &engine.Results{
				Format:        "",
				FormatVersion: "",
				Results: []models.Result{
					{
						Input: models.State{},
						RuleResults: []models.RuleResults{
							{
								Id: "SNYK-CC-AWS-555",
								Results: []models.RuleResult{
									{
										Severity: "high",
									},
								},
							},
							{
								Id: "SNYK-CC-AWS-419",
								Results: []models.RuleResult{
									{
										Severity: "low",
									},
								},
							},
							{
								Id: "SNYK-CC-GCP-100",
								Results: []models.RuleResult{
									{
										Severity: "high",
									},
								},
							},
							{
								Id: "SNYK-CC-TF-5",
								Results: []models.RuleResult{
									{
										Severity: "high",
									},
								},
							},
						},
					},
				},
			},
			output: &engine.Results{
				Format:        "",
				FormatVersion: "",
				Results: []models.Result{
					{
						Input: models.State{},
						RuleResults: []models.RuleResults{
							{
								Id: "SNYK-CC-AWS-555",
								Results: []models.RuleResult{
									{
										Severity: "high",
									},
								},
							},
							{
								Id: "SNYK-CC-AWS-419",
								Results: []models.RuleResult{
									{
										Severity: "medium",
									},
								},
							},
							{
								Id: "SNYK-CC-TF-5",
								Results: []models.RuleResult{
									{
										Severity: "low",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			customSeverities := map[string]string{
				"SNYK-CC-AWS-419": "medium",
				"SNYK-CC-GCP-100": "none",
				"SNYK-CC-TF-5":    "low",
			}

			require.Equal(t, test.output, applyCustomSeverities(test.input, customSeverities))
		})
	}
}
