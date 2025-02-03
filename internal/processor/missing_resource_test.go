package processor

import (
	"encoding/json"
	"testing"

	"github.com/snyk/cli-extension-iac/internal/engine"
	"github.com/snyk/policy-engine/pkg/models"
	"github.com/stretchr/testify/require"
)

func deepCopy(r *engine.Results) *engine.Results {
	resultsJson, err := json.Marshal(r)
	if err != nil {
		return nil
	}
	clone := engine.Results{}
	if err := json.Unmarshal(resultsJson, &clone); err != nil {
		return nil
	}
	return &clone
}

func TestFilterMissingResources(t *testing.T) {
	fixtureBase := &engine.Results{
		Results: []models.Result{
			{
				Input: models.State{
					InputType: "tf_plan",
					Resources: map[string]map[string]models.ResourceState{
						"aws_security_group_rule": {
							"aws_security_group_rule.snyk": models.ResourceState{
								Id:           "aws_security_group_rule.snyk",
								ResourceType: "aws_security_group_rule",
								Namespace:    "plan.json",
							},
						},
					},
				},
				RuleResults: []models.RuleResults{
					{
						Id: "SNYK-CC-00747",
						Results: []models.RuleResult{
							{
								ResourceId:        "aws_security_group.snyk",
								ResourceType:      "aws_security_group",
								ResourceNamespace: "plan.json",
								Resources: []*models.RuleResultResource{
									{
										Id:        "aws_security_group.snyk",
										Type:      "aws_security_group",
										Namespace: "plan.json",
									},
									{
										Id:        "aws_security_group_rule.snyk",
										Type:      "aws_security_group_rule",
										Namespace: "plan.json",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// same as base fixture, but with "cfn" type
	fixtureCfn := deepCopy(fixtureBase)
	for i := range fixtureCfn.Results {
		fixtureCfn.Results[i].Input.InputType = "cfn"
	}

	// same as base fixture, but with no input resources for results
	fixtureNoInputResources := deepCopy(fixtureBase)
	for i := range fixtureNoInputResources.Results {
		fixtureNoInputResources.Results[i].Input.Resources = map[string]map[string]models.ResourceState{}
	}

	// same as base fixture, but with the correct rule result resource
	fixtureCorrect := deepCopy(fixtureBase)
	fixtureCorrect.Results[0].RuleResults[0].Results[0].ResourceId = "aws_security_group_rule.snyk"
	fixtureCorrect.Results[0].RuleResults[0].Results[0].ResourceType = "aws_security_group_rule"
	fixtureCorrect.Results[0].RuleResults[0].Results[0].ResourceNamespace = "plan.json"

	t.Parallel()
	tests := []struct {
		name     string
		received *engine.Results
		expected *engine.Results
	}{
		{
			name:     "skips if type is not tf_plan",
			received: fixtureCfn,
			expected: fixtureCfn,
		},
		{
			name:     "skips if no input resources",
			received: fixtureNoInputResources,
			expected: fixtureNoInputResources,
		},
		{
			name:     "adds the missing resource",
			received: fixtureBase,
			expected: fixtureCorrect,
		},
		{
			name:     "leaves it intact if rule result has existing resource",
			received: fixtureCorrect,
			expected: fixtureCorrect,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// copy the received and expected structures as they may be reused
			received := deepCopy(tt.received)
			expected := deepCopy(tt.expected)
			require.Equal(t, expected, filterMissingResources(received))
		})
	}
}
