package engine

import (
	"testing"

	"github.com/snyk/policy-engine/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestTfPlanFilter(t *testing.T) {
	tests := []struct {
		name   string
		input  *models.ResourceState
		output bool
	}{
		{
			name: "returns true if the resourceAction is create",
			input: &models.ResourceState{
				Meta: map[string]interface{}{
					"tfplan": map[string]interface{}{
						"resource_actions": []interface{}{"create"},
					},
				},
			},
			output: true,
		},
		{
			name: "returns true if the resourceAction is update",
			input: &models.ResourceState{
				Meta: map[string]interface{}{
					"tfplan": map[string]interface{}{
						"resource_actions": []interface{}{"update"},
					},
				},
			},
			output: true,
		},
		{
			name: "returns true if the resourceAction includes create",
			input: &models.ResourceState{
				Meta: map[string]interface{}{
					"tfplan": map[string]interface{}{
						"resource_actions": []interface{}{"delete", "create"},
					},
				},
			},
			output: true,
		},
		{
			name: "returns false if the resourceAction is delete",
			input: &models.ResourceState{
				Meta: map[string]interface{}{
					"tfplan": map[string]interface{}{
						"resource_actions": []interface{}{"delete"},
					},
				},
			},
			output: false,
		},
		{
			name: "returns false if the resourceAction is no-op",
			input: &models.ResourceState{
				Meta: map[string]interface{}{
					"tfplan": map[string]interface{}{
						"resource_actions": []interface{}{"no-op"},
					},
				},
			},
			output: false,
		},
		{
			name: "returns true if the a resource is not a Terraform plan",
			input: &models.ResourceState{
				Meta: map[string]interface{}{},
			},
			output: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := tfPlanFilter(test.input)
			require.Equal(t, test.output, result)
		})
	}
}
