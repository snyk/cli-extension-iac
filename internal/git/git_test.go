package git

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSanitizeUrl(t *testing.T) {
	tests := []struct {
		raw      string
		expected string
	}{
		{
			"https://example.com/user/repo.git",
			"https://example.com/user/repo.git",
		},
		{
			"http://example.com/user/repo.git",
			"https://example.com/user/repo.git",
		},
		{
			"ssh://git@example.com/user/repo.git",
			"https://example.com/user/repo.git",
		},
		{
			"git@example.com:user/repo.git",
			"https://example.com/user/repo.git",
		},
		{
			"example.com:user/repo.git",
			"https://example.com/user/repo.git",
		},
	}

	for _, test := range tests {
		t.Run(test.raw, func(t *testing.T) {
			sanitized := sanitizeUrl(test.raw)
			require.Equal(t, test.expected, sanitized)
		})
	}
}
