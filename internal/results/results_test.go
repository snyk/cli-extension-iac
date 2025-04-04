package results_test

import (
	"testing"

	engine "github.com/snyk/cli-extension-iac/internal/policyengine"
	"github.com/snyk/policy-engine/pkg/models"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-iac/internal/results"
)

func TestFromNilEngineResults(t *testing.T) {
	require.Nil(t, results.FromEngineResults(nil, false))
}

func TestResultsVulnerabilities(t *testing.T) {
	tests := []struct {
		name   string
		input  *engine.Results
		output []results.Vulnerability
	}{
		{
			name: "vulnerable result",
			input: &engine.Results{
				Results: []models.Result{
					{
						Input: models.State{
							InputType: "input-type",
						},
						RuleResults: []models.RuleResults{
							{
								Id:          "SNYK-RULE-ID",
								Title:       "rule-title",
								Description: "rule-description",
								Results: []models.RuleResult{
									{
										Passed:            false,
										Ignored:           true,
										Message:           "result-message",
										Remediation:       "result-remediation",
										Severity:          "result-severity",
										ResourceId:        "resource.id",
										ResourceType:      "resource-type",
										ResourceNamespace: "resource-namespace",
										Context:           map[string]interface{}{"key": "value"},
										Resources: []*models.RuleResultResource{
											{
												Id:        "resource.id",
												Type:      "resource-type",
												Namespace: "resource-namespace",
												Location: []models.SourceLocation{
													{
														Filepath: "resource-file",
														Line:     1,
														Column:   2,
													},
												},
												Attributes: []models.RuleResultResourceAttribute{
													{
														Path: []any{"attribute", "nested_attribute"},
														Location: &models.SourceLocation{
															Filepath: "attribute-file",
															Line:     3,
															Column:   4,
														},
													},
												},
											},
										},
									},
								},
								Category: "rule-category",
								Labels:   []string{"rule-label"},
								References: []models.RuleResultsReference{
									{
										Url:   "http://fake/rule-reference",
										Title: "rule-reference",
									},
								},
							},
						},
					},
				},
			},
			output: []results.Vulnerability{
				{
					Rule: results.Rule{
						ID:            "SNYK-RULE-ID",
						Title:         "rule-title",
						Description:   "rule-description",
						Category:      "rule-category",
						Labels:        []string{"rule-label"},
						References:    "http://fake/rule-reference",
						Documentation: "https://security.snyk.io/rules/cloud/SNYK-RULE-ID",
					},
					Message:     "result-message",
					Remediation: "result-remediation",
					Severity:    "result-severity",
					Ignored:     true,
					Context:     map[string]interface{}{"key": "value"},
					Resource: results.Resource{
						Kind:          "input-type",
						ID:            "resource.id",
						Type:          "resource-type",
						Path:          []any{"attribute", "nested_attribute"},
						FormattedPath: "resource.resource[id].attribute.nested_attribute",
						File:          "attribute-file",
						Line:          3,
						Column:        4,
						SourceLocation: []results.Location{
							{
								File:   "attribute-file",
								Line:   3,
								Column: 4,
							},
							{
								File:   "resource-file",
								Line:   1,
								Column: 2,
							},
						},
					},
				},
			},
		},
		{
			name: "passed result",
			input: &engine.Results{
				Results: []models.Result{
					{
						RuleResults: []models.RuleResults{
							{
								Results: []models.RuleResult{
									{
										Passed: true,
									},
								},
							},
						},
					},
				},
			},
			output: nil,
		},
		{
			name: "vulnerable result without attributes",
			input: &engine.Results{
				Results: []models.Result{
					{
						RuleResults: []models.RuleResults{
							{
								Id: "SNYK-RULE-ID",
								Results: []models.RuleResult{
									{
										ResourceId: "resource.id",
										Resources: []*models.RuleResultResource{
											{
												Id: "resource.id",
												Location: []models.SourceLocation{
													{
														Filepath: "resource-file",
														Line:     1,
														Column:   2,
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			output: []results.Vulnerability{
				{
					Rule: results.Rule{
						ID:            "SNYK-RULE-ID",
						Documentation: "https://security.snyk.io/rules/cloud/SNYK-RULE-ID",
					},
					Resource: results.Resource{
						ID:            "resource.id",
						FormattedPath: "resource.resource[id]",
						File:          "resource-file",
						Line:          1,
						Column:        2,
						SourceLocation: []results.Location{
							{
								File:   "resource-file",
								Line:   1,
								Column: 2,
							},
						},
					},
				},
			},
		},
		{
			name: "vulnerable result with multiple attributes",
			input: &engine.Results{
				Results: []models.Result{
					{
						RuleResults: []models.RuleResults{
							{
								Id: "SNYK-RULE-ID",
								Results: []models.RuleResult{
									{
										Resources: []*models.RuleResultResource{
											{
												Attributes: []models.RuleResultResourceAttribute{
													{
														Path: []any{"attribute", "nested_attribute"},
														Location: &models.SourceLocation{
															Filepath: "attribute-1-file",
															Line:     3,
															Column:   4,
														},
													},
													{
														Path: []any{"attribute", "nested_attribute"},
														Location: &models.SourceLocation{
															Filepath: "attribute-2-file",
															Line:     5,
															Column:   6,
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			output: []results.Vulnerability{
				{
					Rule: results.Rule{
						ID:            "SNYK-RULE-ID",
						Documentation: "https://security.snyk.io/rules/cloud/SNYK-RULE-ID",
					},
					Resource: results.Resource{
						Path:          []any{"attribute", "nested_attribute"},
						FormattedPath: "resource.attribute.nested_attribute",
						File:          "attribute-1-file",
						Line:          3,
						Column:        4,
					},
				},
			},
		},
		{
			name: "vulnerable result with no resources",
			input: &engine.Results{
				Results: []models.Result{
					{
						RuleResults: []models.RuleResults{
							{
								Results: []models.RuleResult{
									{
										Resources: []*models.RuleResultResource{},
									},
								},
								Category: "rule-category",
								Labels:   []string{"rule-label"}, References: []models.RuleResultsReference{
									{
										Url:   "http://fake/rule-reference",
										Title: "rule-reference",
									},
								},
							},
						},
					},
				},
			},
			output: nil,
		},
		{
			name: "vulnerable result with multiple resources",
			input: &engine.Results{
				Results: []models.Result{
					{
						RuleResults: []models.RuleResults{
							{
								Id: "SNYK-RULE-ID",
								Results: []models.RuleResult{
									{
										ResourceId:        "primary-resource.id",
										ResourceType:      "primary-resource-type",
										ResourceNamespace: "primary-resource-namespace",
										Resources: []*models.RuleResultResource{
											{
												Id:        "primary-resource.id",
												Type:      "primary-resource-type",
												Namespace: "primary-resource-namespace",
											},
											{
												Id:        "secondary-resource.id",
												Type:      "secondary-resource-type",
												Namespace: "secondary-resource-namespace",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			output: []results.Vulnerability{
				{
					Rule: results.Rule{
						ID:            "SNYK-RULE-ID",
						Documentation: "https://security.snyk.io/rules/cloud/SNYK-RULE-ID",
					},
					Resource: results.Resource{
						ID:            "primary-resource.id",
						Type:          "primary-resource-type",
						FormattedPath: "resource.primary-resource[id]",
					},
				},
			},
		},
		{
			name: "vulnerable result with custom rule",
			input: &engine.Results{
				Results: []models.Result{
					{
						RuleResults: []models.RuleResults{
							{
								Id: "SNYK-RULE-ID",
								Results: []models.RuleResult{
									{
										ResourceId: "resource.id",
										Resources: []*models.RuleResultResource{
											{
												Id: "resource.id",
												Location: []models.SourceLocation{
													{
														Filepath: "resource-file",
														Line:     1,
														Column:   2,
													},
												},
											},
										},
									},
								},
							},
							{
								Id: "OTHER-RULE-ID",
								Results: []models.RuleResult{
									{
										ResourceId: "resource.id_2",
										Resources: []*models.RuleResultResource{
											{
												Id: "resource.id_2",
												Location: []models.SourceLocation{
													{
														Filepath: "other-resource-file",
														Line:     10,
														Column:   20,
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			output: []results.Vulnerability{
				{
					Rule: results.Rule{
						ID:            "SNYK-RULE-ID",
						Documentation: "https://security.snyk.io/rules/cloud/SNYK-RULE-ID",
					},
					Resource: results.Resource{
						ID:            "resource.id",
						FormattedPath: "resource.resource[id]",
						File:          "resource-file",
						Line:          1,
						Column:        2,
						SourceLocation: []results.Location{
							{
								File:   "resource-file",
								Line:   1,
								Column: 2,
							},
						},
					},
				},
				{
					Rule: results.Rule{
						ID:                      "OTHER-RULE-ID",
						IsGeneratedByCustomRule: true,
					},
					Resource: results.Resource{
						ID:            "resource.id_2",
						FormattedPath: "resource.resource[id_2]",
						File:          "other-resource-file",
						Line:          10,
						Column:        20,
						SourceLocation: []results.Location{
							{
								File:   "other-resource-file",
								Line:   10,
								Column: 20,
							},
						},
					},
				},
			},
		},
		{
			name: "vulnerable result with tags",
			input: &engine.Results{
				Results: []models.Result{
					{
						Input: models.State{
							InputType: "input-type",
							Resources: map[string]map[string]models.ResourceState{
								"resource-type": {
									"resource-id": {
										Id:           "resource-id",
										ResourceType: "resource-type",
										Meta: map[string]any{
											"location": []any{},
										},
										Tags: map[string]string{
											"test":   "value",
											"team":   "iac",
											"region": "eu",
										},
									},
								},
							},
						},
						RuleResults: []models.RuleResults{
							{
								Id: "SNYK-RULE-ID",
								Results: []models.RuleResult{
									{
										ResourceId:   "resource-id",
										ResourceType: "resource-type",
										Resources: []*models.RuleResultResource{
											{
												Id:   "resource-id",
												Type: "resource-type",
												Location: []models.SourceLocation{
													{
														Filepath: "resource-file",
														Line:     1,
														Column:   2,
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			output: []results.Vulnerability{
				{
					Rule: results.Rule{
						ID:            "SNYK-RULE-ID",
						Documentation: "https://security.snyk.io/rules/cloud/SNYK-RULE-ID",
					},
					Resource: results.Resource{
						ID:            "resource-id",
						Type:          "resource-type",
						FormattedPath: "resource.resource-id",
						File:          "resource-file",
						Kind:          "input-type",
						Line:          1,
						Column:        2,
						SourceLocation: []results.Location{
							{
								File:   "resource-file",
								Line:   1,
								Column: 2,
							},
						},
						Tags: map[string]string{
							"test":   "value",
							"team":   "iac",
							"region": "eu",
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := results.FromEngineResults(test.input, false).Vulnerabilities
			require.ElementsMatch(t, test.output, result)
		})
	}
}

func TestResultsPassedVulnerabilities(t *testing.T) {
	tests := []struct {
		name                         string
		input                        *engine.Results
		output                       []results.Vulnerability
		includePassedVulnerabilities bool
	}{
		{
			name: "vulnerable result",
			input: &engine.Results{
				Results: []models.Result{
					{
						Input: models.State{
							InputType: "input-type",
						},
						RuleResults: []models.RuleResults{
							{
								Id:          "SNYK-RULE-ID",
								Title:       "rule-title",
								Description: "rule-description",
								Results: []models.RuleResult{
									{
										Passed: false,
									},
								},
								Category: "rule-category",
								Labels:   []string{"rule-label"},
								References: []models.RuleResultsReference{
									{
										Url:   "http://fake/rule-reference",
										Title: "rule-reference",
									},
								},
							},
						},
					},
				},
			},
			output:                       nil,
			includePassedVulnerabilities: true,
		},
		{
			name: "passed result",
			input: &engine.Results{
				Results: []models.Result{
					{
						Input: models.State{
							InputType: "input-type",
						},
						RuleResults: []models.RuleResults{
							{
								Id:          "SNYK-RULE-ID",
								Title:       "rule-title",
								Description: "rule-description",
								Results: []models.RuleResult{
									{
										Passed:            true,
										Ignored:           true,
										Message:           "result-message",
										Remediation:       "result-remediation",
										Severity:          "result-severity",
										ResourceId:        "resource.id",
										ResourceType:      "resource-type",
										ResourceNamespace: "resource-namespace",
										Resources: []*models.RuleResultResource{
											{
												Id:        "resource.id",
												Type:      "resource-type",
												Namespace: "resource-namespace",
												Location: []models.SourceLocation{
													{
														Filepath: "resource-file",
														Line:     1,
														Column:   2,
													},
												},
												Attributes: []models.RuleResultResourceAttribute{
													{
														Path: []any{"attribute", "nested_attribute"},
														Location: &models.SourceLocation{
															Filepath: "attribute-file",
															Line:     3,
															Column:   4,
														},
													},
												},
											},
										},
									},
								},
								Category: "rule-category",
								Labels:   []string{"rule-label"},
								References: []models.RuleResultsReference{
									{
										Url:   "http://fake/rule-reference",
										Title: "rule-reference",
									},
								},
							},
						},
					},
				},
			},
			output: []results.Vulnerability{
				{
					Rule: results.Rule{
						ID:            "SNYK-RULE-ID",
						Title:         "rule-title",
						Description:   "rule-description",
						Category:      "rule-category",
						Labels:        []string{"rule-label"},
						References:    "http://fake/rule-reference",
						Documentation: "https://security.snyk.io/rules/cloud/SNYK-RULE-ID",
					},
					Message:     "result-message",
					Remediation: "result-remediation",
					Severity:    "result-severity",
					Ignored:     true,
					Resource: results.Resource{
						Kind:          "input-type",
						ID:            "resource.id",
						Type:          "resource-type",
						Path:          []any{"attribute", "nested_attribute"},
						FormattedPath: "resource.resource[id].attribute.nested_attribute",
						File:          "attribute-file",
						Line:          3,
						Column:        4,
						SourceLocation: []results.Location{
							{
								File:   "attribute-file",
								Line:   3,
								Column: 4,
							},
							{
								File:   "resource-file",
								Line:   1,
								Column: 2,
							},
						},
					},
				},
			},
			includePassedVulnerabilities: true,
		},
		{
			name: "passed result but includePassedVulnerabilities=false",
			input: &engine.Results{
				Results: []models.Result{
					{
						Input: models.State{
							InputType: "input-type",
						},
						RuleResults: []models.RuleResults{
							{
								Id:          "SNYK-RULE-ID",
								Title:       "rule-title",
								Description: "rule-description",
								Results: []models.RuleResult{
									{
										Passed:            true,
										Ignored:           true,
										Message:           "result-message",
										Remediation:       "result-remediation",
										Severity:          "result-severity",
										ResourceId:        "resource.id",
										ResourceType:      "resource-type",
										ResourceNamespace: "resource-namespace",
										Resources: []*models.RuleResultResource{
											{
												Id:        "resource.id",
												Type:      "resource-type",
												Namespace: "resource-namespace",
												Location: []models.SourceLocation{
													{
														Filepath: "resource-file",
														Line:     1,
														Column:   2,
													},
												},
												Attributes: []models.RuleResultResourceAttribute{
													{
														Path: []any{"attribute", "nested_attribute"},
														Location: &models.SourceLocation{
															Filepath: "attribute-file",
															Line:     3,
															Column:   4,
														},
													},
												},
											},
										},
									},
								},
								Category: "rule-category",
								Labels:   []string{"rule-label"},
								References: []models.RuleResultsReference{
									{
										Url:   "http://fake/rule-reference",
										Title: "rule-reference",
									},
								},
							},
						},
					},
				},
			},
			output:                       []results.Vulnerability{},
			includePassedVulnerabilities: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := results.FromEngineResults(test.input, test.includePassedVulnerabilities).PassedVulnerabilities
			require.ElementsMatch(t, test.output, result)
		})
	}
}

func TestResultsResource(t *testing.T) {
	tests := []struct {
		name   string
		input  *engine.Results
		output []results.Resource
	}{
		{
			name: "resource without location",
			input: &engine.Results{
				Results: []models.Result{
					{
						Input: models.State{
							InputType: "input-type",
							Resources: map[string]map[string]models.ResourceState{
								"resource-type": {
									"resource-id": {
										Id:           "resource-id",
										ResourceType: "resource-type",
									},
								},
							},
						},
					},
				},
			},
			output: []results.Resource{
				{
					ID:   "resource-id",
					Type: "resource-type",
					Kind: "input-type",
				},
			},
		},
		{
			name: "resource with nil location",
			input: &engine.Results{
				Results: []models.Result{
					{
						Input: models.State{
							InputType: "input-type",
							Resources: map[string]map[string]models.ResourceState{
								"resource-type": {
									"resource-id": {
										Id:           "resource-id",
										ResourceType: "resource-type",
										Meta: map[string]any{
											"location": nil,
										},
									},
								},
							},
						},
					},
				},
			},
			output: []results.Resource{
				{
					ID:   "resource-id",
					Type: "resource-type",
					Kind: "input-type",
				},
			},
		},
		{
			name: "resource with empty location",
			input: &engine.Results{
				Results: []models.Result{
					{
						Input: models.State{
							InputType: "input-type",
							Resources: map[string]map[string]models.ResourceState{
								"resource-type": {
									"resource-id": {
										Id:           "resource-id",
										ResourceType: "resource-type",
										Meta: map[string]any{
											"location": []any{},
										},
									},
								},
							},
						},
					},
				},
			},
			output: []results.Resource{
				{
					ID:   "resource-id",
					Type: "resource-type",
					Kind: "input-type",
				},
			},
		},
		{
			name: "resource with location",
			input: &engine.Results{
				Results: []models.Result{
					{
						Input: models.State{
							InputType: "input-type",
							Resources: map[string]map[string]models.ResourceState{
								"resource-type": {
									"resource-id": {
										Id:           "resource-id",
										ResourceType: "resource-type",
										Meta: map[string]any{
											"location": []any{
												map[string]any{
													"filePath": "resource-file",
													"line":     41,
													"column":   42,
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			output: []results.Resource{
				{
					ID:     "resource-id",
					Type:   "resource-type",
					Kind:   "input-type",
					File:   "resource-file",
					Line:   41,
					Column: 42,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resources := results.FromEngineResults(test.input, false).Resources
			require.ElementsMatch(t, test.output, resources)
		})
	}
}
