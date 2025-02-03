package results

import (
	"testing"

	engine "github.com/snyk/cli-extension-iac/internal/policyengine"
	"github.com/snyk/policy-engine/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestStubResources(t *testing.T) {
	tests := []struct {
		name        string
		inputType   string
		expectEmpty bool
	}{
		{
			name:        "stubs input resource attributes for cfn",
			inputType:   "cfn",
			expectEmpty: true,
		},
		{
			name:        "skips stubbing resource attributs for tf_hcl",
			inputType:   "tf_hcl",
			expectEmpty: false,
		},
		{
			name:        "skips stubbing resource attributs for tf_plan",
			inputType:   "tf_plan",
			expectEmpty: false,
		},
		{
			name:        "skips stubbing resource attributs for tf_state",
			inputType:   "tf_state",
			expectEmpty: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := &engine.Results{
				Format:        "results",
				FormatVersion: "1.0.0",
				Results: []models.Result{
					{
						Input: models.State{
							Format:              "input",
							FormatVersion:       "0.1.0",
							InputType:           test.inputType,
							EnvironmentProvider: "iac",
							Meta: map[string]interface{}{
								"filepath": "file-path",
							},
							Resources: map[string]map[string]models.ResourceState{
								"resource-type": {
									"resource.id": models.ResourceState{
										Id:           "resource.id",
										ResourceType: "resource-type",
										Namespace:    "file-path",
										Meta: map[string]interface{}{
											"location": []map[string]interface{}{
												{
													"filepath": "file-path.yaml",
													"line":     1,
													"column":   1,
												},
											},
											"region": "us-west-2",
											"terraform": map[string]interface{}{
												"provider_config": map[string]interface{}{
													"region": "us-west-2",
												},
											},
										},
										Attributes: map[string]interface{}{
											"attribute-key-1": "attribute-value-1",
											"attribute-key-2": "attribute-value-2",
										},
									},
								},
							},
							Scope: map[string]interface{}{
								"filepath": "file-path",
							},
						},
						RuleResults: []models.RuleResults{
							{
								Id:          "rule-id",
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
							},
						},
					},
				},
			}

			result := StubResources(input)

			// require resource attributes to be empty
			require.Equal(t, 1, len(result.Results))
			for _, resources := range result.Results[0].Input.Resources {
				for _, resource := range resources {
					if test.expectEmpty {
						require.Empty(t, resource.Attributes)
					} else {
						require.NotEmpty(t, resource.Attributes)
					}
				}
			}

			// require other values to stay the same
			require.Equal(t, input.Format, result.Format)
			require.Equal(t, input.FormatVersion, result.FormatVersion)
			require.Equal(t, input.Results[0].RuleResults, result.Results[0].RuleResults)
		})
	}
}
