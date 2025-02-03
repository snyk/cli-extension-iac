package processor

import (
	"testing"
	"time"

	"github.com/snyk/cli-extension-iac/internal/results"
	"github.com/stretchr/testify/require"
)

type mockMatcher func(id string, now time.Time, parts ...string) bool

func (m mockMatcher) Match(id string, now time.Time, parts ...string) bool {
	return m(id, now, parts...)
}

func TestFilterVulnerabilitiesByIgnores(t *testing.T) {
	tests := []struct {
		name    string
		input   *results.Results
		matcher func(t *testing.T) matcher
		output  *results.Results
	}{
		{
			name:   "nil",
			input:  nil,
			output: nil,
			matcher: func(t *testing.T) matcher {
				return mockMatcher(func(id string, now time.Time, parts ...string) bool {
					panic("matcher should not be used")
				})
			},
		},
		{
			name: "match",
			input: &results.Results{
				Vulnerabilities: []results.Vulnerability{
					{
						Rule: results.Rule{
							ID: "id",
						},
						Resource: results.Resource{
							File:          "file",
							FormattedPath: "a.b.c",
						},
					},
				},
			},
			output: &results.Results{
				Vulnerabilities: nil,
				Metadata: results.Metadata{
					IgnoredCount: 1,
				},
			},
			matcher: func(t *testing.T) matcher {
				return mockMatcher(func(id string, now time.Time, parts ...string) bool {
					require.Equal(t, id, "id")
					require.Equal(t, parts, []string{"file", "a", "b", "c"})
					return true
				})
			},
		},
		{
			name: "no match",
			input: &results.Results{
				Vulnerabilities: []results.Vulnerability{
					{
						Rule: results.Rule{
							ID: "id",
						},
						Resource: results.Resource{
							File:          "file",
							FormattedPath: "a.b.c",
						},
					},
				},
			},
			output: &results.Results{
				Vulnerabilities: []results.Vulnerability{
					{
						Rule: results.Rule{
							ID: "id",
						},
						Resource: results.Resource{
							File:          "file",
							FormattedPath: "a.b.c",
						},
					},
				},
			},
			matcher: func(t *testing.T) matcher {
				return mockMatcher(func(id string, now time.Time, parts ...string) bool {
					require.Equal(t, id, "id")
					require.Equal(t, parts, []string{"file", "a", "b", "c"})
					return false
				})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := filterVulnerabilitiesByIgnores(test.input, test.matcher(t), time.Now())
			require.Equal(t, test.output, got)
		})
	}
}
