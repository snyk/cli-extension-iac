package ignore_test

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-iac/internal/ignore"
)

func TestMatcherPath(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		path    string
		matches bool
	}{
		{
			name:    "exact match",
			pattern: "foo",
			path:    "foo",
			matches: true,
		},
		{
			name:    "invalid exact match",
			pattern: "foo",
			path:    "bar",
			matches: false,
		},
		{
			name:    "exact deep match",
			pattern: "foo > bar",
			path:    "foo.bar",
			matches: true,
		},
		{
			name:    "invalid exact deep match",
			pattern: "foo > bar",
			path:    "foo.qux",
			matches: false,
		},
		{
			name:    "exact pattern too long",
			pattern: "foo > bar",
			path:    "foo",
			matches: false,
		},
		{
			name:    "exact pattern too short",
			pattern: "foo",
			path:    "foo.bar",
			matches: false,
		},
		{
			name:    "wildcard match",
			pattern: "*",
			path:    "foo",
			matches: true,
		},
		{
			name:    "wildcard deep match",
			pattern: "foo > *",
			path:    "foo.bar",
			matches: true,
		},
		{
			name:    "wildcard invalid prefix",
			pattern: "foo > *",
			path:    "qux.bar",
			matches: false,
		},
		{
			name:    "wildcard pattern too short",
			pattern: "foo > *",
			path:    "foo.bar.qux",
			matches: true,
		},
		{
			name:    "wildcard pattern too long",
			pattern: "foo > bar > *",
			path:    "foo.bar",
			matches: false,
		},
		{
			name:    "wildcard middle",
			pattern: "foo > * > qux",
			path:    "foo.bar.qux",
			matches: true,
		},
		{
			name:    "empty path component",
			pattern: "foo > ",
			path:    "foo",
			matches: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now := time.Now()

			var m ignore.Matcher

			require.NoError(t, m.AddIgnore("RULE-1", now.Add(time.Hour), test.pattern))

			match := m.Match("RULE-1", now, strings.Split(test.path, ".")...)

			if test.matches {
				require.True(t, match)
			} else {
				require.False(t, match)
			}
		})
	}
}

func TestMatcherExpired(t *testing.T) {
	now := time.Now()

	var m ignore.Matcher

	require.NoError(t, m.AddIgnore("RULE-1", now.Add(-time.Hour), "foo"))

	require.False(t, m.Match("RULE-1", now, "foo"))
}

func TestMatcherNoExpirationDate(t *testing.T) {
	var m ignore.Matcher

	require.NoError(t, m.AddIgnore("RULE-1", time.Time{}, "foo"))

	require.True(t, m.Match("RULE-1", time.Now(), "foo"))
}

func TestMatcherInvalidPath(t *testing.T) {
	var m ignore.Matcher

	require.ErrorContains(t, m.AddIgnore("RULE-1", time.Now(), ""), "empty pattern")
}

func TestMatcherInvalidPathComponent(t *testing.T) {
	var m ignore.Matcher

	require.NoError(t, m.AddIgnore("RULE-1", time.Now(), "foo >  > bar"))
}

func TestMatcherInvalidVulnerabilityID(t *testing.T) {
	var m ignore.Matcher

	require.ErrorContains(t, m.AddIgnore("", time.Now(), "foo"), "empty vulnerability ID")
}

func TestMatcherAtLeastOneMatch(t *testing.T) {
	now := time.Now()

	var m ignore.Matcher

	require.NoError(t, m.AddIgnore("RULE-1", now.Add(time.Hour), "foo"))
	require.NoError(t, m.AddIgnore("RULE-1", now.Add(time.Hour), "bar"))

	require.True(t, m.Match("RULE-1", now, "foo"))
}

func TestMatcherVulnerabilityNotFound(t *testing.T) {
	now := time.Now()

	var m ignore.Matcher

	require.NoError(t, m.AddIgnore("RULE-1", now.Add(time.Hour), "foo"))

	require.False(t, m.Match("RULE-2", now, "foo"))
}

func TestMatcherEmpty(t *testing.T) {
	var m ignore.Matcher

	require.False(t, m.Match("RULE-1", time.Now(), "foo"))
}
