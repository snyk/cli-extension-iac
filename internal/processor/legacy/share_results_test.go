package legacy

import (
	"testing"

	"github.com/snyk/cli-extension-iac/internal/registry"
	"github.com/stretchr/testify/require"
)

func stringPtr(s string) *string {
	return &s
}

func TestFormatAttributes(t *testing.T) {
	type testCase struct {
		name             string
		resultsProcessor ShareResults
		expected         registry.Attributes
	}

	testCases := []testCase{
		{
			name: "flags were not provided",
			resultsProcessor: ShareResults{
				ProjectBusinessCriticality: nil,
				ProjectEnvironment:         nil,
				ProjectLifecycle:           nil,
			},
			expected: registry.Attributes{},
		},
		{
			name: "flags provided - no value provided",
			resultsProcessor: ShareResults{
				ProjectBusinessCriticality: stringPtr(""),
				ProjectEnvironment:         stringPtr(""),
				ProjectLifecycle:           stringPtr(""),
			},
			expected: registry.Attributes{
				Criticality: &[]string{},
				Environment: &[]string{},
				Lifecycle:   &[]string{},
			},
		},
		{
			name: "flags provided - value provided",
			resultsProcessor: ShareResults{
				ProjectBusinessCriticality: stringPtr("critical,high"),
				ProjectEnvironment:         stringPtr("frontend,backend"),
				ProjectLifecycle:           stringPtr("production"),
			},
			expected: registry.Attributes{
				Criticality: &[]string{"critical", "high"},
				Environment: &[]string{"frontend", "backend"},
				Lifecycle:   &[]string{"production"},
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			formattedAttributes := &registry.Attributes{
				Criticality: stringPtrToStringSlicePtr(test.resultsProcessor.ProjectBusinessCriticality),
				Environment: stringPtrToStringSlicePtr(test.resultsProcessor.ProjectEnvironment),
				Lifecycle:   stringPtrToStringSlicePtr(test.resultsProcessor.ProjectLifecycle),
			}
			require.Equal(t, &test.expected, formattedAttributes)
		})
	}
}

func TestFormatTags(t *testing.T) {
	type testCase struct {
		name             string
		resultsProcessor ShareResults
		expected         []registry.Tag
	}

	testCases := []testCase{
		{
			name: "flag was not provided",
			resultsProcessor: ShareResults{
				ProjectTags: nil,
			},
			expected: []registry.Tag{},
		},
		{
			name: "flag provided - no value provided",
			resultsProcessor: ShareResults{
				ProjectTags: stringPtr(""),
			},
			expected: []registry.Tag{},
		},
		{
			name: "flag provided - value provided",
			resultsProcessor: ShareResults{
				ProjectTags: stringPtr("key1=value1,key2=value2"),
			},
			expected: []registry.Tag{
				{
					Key:   "key1",
					Value: "value1",
				},
				{
					Key:   "key2",
					Value: "value2",
				},
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			formattedTags := test.resultsProcessor.formatTags()
			require.Equal(t, test.expected, formattedTags)
		})
	}
}

func TestContributorsAdded(t *testing.T) {
	type testCase struct {
		name             string
		resultsProcessor ShareResults
		expected         bool
	}

	testCases := []testCase{
		{
			name: "allow analytics flag was not provided",
			resultsProcessor: ShareResults{
				AllowAnalytics: false,
			},
			expected: false,
		},
		{
			name: "allow analytics flag was provided",
			resultsProcessor: ShareResults{
				AllowAnalytics: true,
			},
			expected: true,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			contributors, _ := test.resultsProcessor.listContributors()
			contributorsExist := contributors != nil
			require.Equal(t, test.expected, contributorsExist)
		})
	}
}
