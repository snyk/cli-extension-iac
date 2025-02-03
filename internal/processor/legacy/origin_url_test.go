package legacy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFormatOriginUrl(t *testing.T) {
	tests := []struct {
		name      string
		originUrl string
		output    string
	}{
		{
			name:      "user@host type of git origin url",
			originUrl: "user@host.xz:path/to/repo.git/",
			output:    "http://host.xz/path/to/repo.git",
		},
		{
			name:      "host:path type of git origin url",
			originUrl: "host.xz:/path/to/repo.git/",
			output:    "http://host.xz/path/to/repo.git",
		},
		{
			name:      "git:// type of git origin url",
			originUrl: "git://host.xz/path/to/repo.git/",
			output:    "git://host.xz/path/to/repo.git/",
		},
		{
			name:      "http git origin url",
			originUrl: "http://host.xz/path/to/repo.git/",
			output:    "http://host.xz/path/to/repo.git",
		},
		{
			name:      "https git origin url",
			originUrl: "https://host.xz:1234/path/to/repo.git/",
			output:    "http://host.xz:1234/path/to/repo.git",
		},
		{
			name:      "git@ type of git origin url",
			originUrl: "git@host.xz:organization/repo.git?ref=test",
			output:    "http://host.xz/organization/repo.git",
		},
		{
			name:      "ssh type of git origin url",
			originUrl: "ssh://host.xz:1234/path/to/repo.git/",
			output:    "http://host.xz:1234/path/to/repo.git",
		},
		{
			name:      "ftp type of git origin url",
			originUrl: "ftp://host.xz:1234/path/to/repo.git/",
			output:    "http://host.xz:1234/path/to/repo.git",
		},
		{
			name:      "ftps type of git origin url",
			originUrl: "ftps://host.xz/path/to/repo.git/",
			output:    "http://host.xz/path/to/repo.git",
		},
		{
			name:      "file:// type of git origin url",
			originUrl: "file:///path/to/repo.git/",
			output:    "file:///path/to/repo.git/",
		},
		{
			name:      "file path type of git origin url",
			originUrl: "/path/to/repo.git/",
			output:    "file:///path/to/repo.git/",
		},
		{
			name:      "rsync:// type of git origin url",
			originUrl: "rsync://host.xz/path/to/repo.git/",
			output:    "rsync://host.xz/path/to/repo.git/",
		},
		{
			name:      "git+ssh:// type of git origin url",
			originUrl: "git+ssh://host.xz/path/to/repo.git/",
			output:    "git+ssh://host.xz/path/to/repo.git/",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, _ := formatOriginUrl(test.originUrl)
			require.Equal(t, test.output, result)
		})
	}
}
