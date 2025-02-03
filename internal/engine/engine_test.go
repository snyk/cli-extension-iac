package engine

import (
	"testing"

	"github.com/snyk/policy-engine/pkg/models"
	"github.com/stretchr/testify/assert"
)

func Test_calculateSuppressionInfo(t *testing.T) {
	type args struct {
		withResolver    *models.Results
		withoutResolver *models.Results
	}
	tests := []struct {
		name string
		args args
		want map[string][]string
	}{
		{
			name: "Two suppressed rule with same resource in multiple input",
			args: args{
				withResolver: &models.Results{
					Results: []models.Result{
						{
							Input: models.State{Meta: map[string]interface{}{
								"filepath": "test",
							}},
							RuleResults: []models.RuleResults{
								{
									Id: "some-rule",
									Results: []models.RuleResult{
										{
											ResourceId: "resource1",
											Passed:     true,
										},
										{
											ResourceId: "resource3",
											Passed:     false,
										},
										{
											ResourceId: "resource4",
											Passed:     true,
										},
									},
								},
							},
						},
						{
							Input: models.State{Meta: map[string]interface{}{
								"filepath": "correct",
							}},
							RuleResults: []models.RuleResults{
								{
									Id: "some-rule",
									Results: []models.RuleResult{
										{
											ResourceId: "resource2",
											Passed:     true,
										},
										{
											ResourceId: "resource3",
											Passed:     false,
										},
										{
											ResourceId: "resource4",
											Passed:     true,
										},
									},
								},
							},
						},
					},
				},
				withoutResolver: &models.Results{
					Results: []models.Result{
						{
							Input: models.State{Meta: map[string]interface{}{
								"filepath": "test",
							}},
							RuleResults: []models.RuleResults{
								{
									Id: "some-rule",
									Results: []models.RuleResult{
										{
											ResourceId: "resource1",
											Passed:     false,
										},
										{
											ResourceId: "resource3",
											Passed:     false,
										},
										{
											ResourceId: "resource4",
											Passed:     true,
										},
									},
								},
							},
						},
						{
							Input: models.State{Meta: map[string]interface{}{
								"filepath": "correct",
							}},
							RuleResults: []models.RuleResults{
								{
									Id: "some-rule",
									Results: []models.RuleResult{
										{
											ResourceId: "resource2",
											Passed:     false,
										},
										{
											ResourceId: "resource3",
											Passed:     false,
										},
										{
											ResourceId: "resource4",
											Passed:     true,
										},
									},
								},
							},
						},
					},
				},
			},
			want: map[string][]string{
				"some-rule": {"resource1", "resource2"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateSuppressionInfo(tt.args.withResolver, tt.args.withoutResolver)
			assert.Equal(t, tt.want, got)
		})
	}
}
