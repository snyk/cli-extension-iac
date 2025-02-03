package ignore_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/snyk/cli-extension-iac/internal/ignore"
	"github.com/stretchr/testify/require"
)

func TestNewMatcherFromPolicy(t *testing.T) {
	type match struct {
		ID    string
		Parts string
		Now   string
	}

	tests := []struct {
		name    string
		matches []match
	}{
		{
			name:    "comment-only.yaml",
			matches: nil,
		},
		{
			name: "no-expires.yaml",
			matches: []match{
				{ID: "SNYK-JS-ANSIREGEX-1583908", Parts: "foo > bar > baz", Now: "2022-01-01T00:00:00.000Z"},
				{ID: "SNYK-CC-K8S-4", Parts: "test/fixtures/kubernetes/pod-privileged.yaml", Now: "2022-01-01T00:00:00.000Z"},
			},
		},
		{
			name: "multiple-rules.yaml",
			matches: []match{
				{ID: "SNYK-JS-ANSIREGEX-1583908", Parts: "foo > bar > baz", Now: "2022-01-01T00:00:00.000Z"},
				{ID: "SNYK-CC-K8S-4", Parts: "test/fixtures/kubernetes/pod-privileged.yaml", Now: "2022-02-01T00:00:00.000Z"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matcher, err := ignore.NewMatcherFromPolicy(readFile(t, test.name))
			require.NoError(t, err)

			for _, m := range test.matches {
				require.True(t, matcher.Match(m.ID, newTime(t, m.Now), strings.Split(m.Parts, " > ")...), "match on %s - %s - %s", m.ID, m.Now, m.Parts)
			}
		})
	}
}

func newTime(t *testing.T, s string) time.Time {
	t.Helper()

	parsed, err := time.Parse(time.RFC3339, s)
	require.NoError(t, err)

	return parsed
}

func readFile(t *testing.T, name string) []byte {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)

	return data
}
