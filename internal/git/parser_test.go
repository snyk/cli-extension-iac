package git

import (
	"github.com/stretchr/testify/require"
	"net/url"
	"testing"
)

func TestParseUrl(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		output *url.URL
	}{
		{
			name:   "unrecognised path - defaults to local url",
			input:  "user@host",
			output: &url.URL{Scheme: "file", Path: "user@host"},
		},
		{
			name:   "user@host type of git origin url",
			input:  "user@host.xz:path/to/repo.git/",
			output: &url.URL{Scheme: "ssh", Host: "host.xz", Path: "path/to/repo.git/", User: url.User("user")},
		},
		{
			name:   "host:path type of git origin url",
			input:  "host.xz:/path/to/repo.git/",
			output: &url.URL{Scheme: "ssh", Host: "host.xz", Path: "/path/to/repo.git/"},
		},
		{
			name:   "git:// type of git origin url",
			input:  "git://host.xz/path/to/repo.git/",
			output: &url.URL{Scheme: "git", Host: "host.xz", Path: "/path/to/repo.git/"},
		},
		{
			name:   "http git origin url",
			input:  "http://host.xz/path/to/repo.git/",
			output: &url.URL{Scheme: "http", Host: "host.xz", Path: "/path/to/repo.git/"},
		},
		{
			name:   "https git origin url",
			input:  "https://host.xz:1234/path/to/repo.git/",
			output: &url.URL{Scheme: "https", Host: "host.xz:1234", Path: "/path/to/repo.git/"},
		},
		{
			name:   "git@ type of git origin url",
			input:  "git@host.xz:organization/repo.git?ref=test",
			output: &url.URL{Scheme: "ssh", Host: "host.xz", Path: "organization/repo.git", User: url.User("git"), RawQuery: "ref=test"},
		},
		{
			name:   "ssh type of git origin url",
			input:  "ssh://host.xz:1234/path/to/repo.git/",
			output: &url.URL{Scheme: "ssh", Host: "host.xz:1234", Path: "/path/to/repo.git/"},
		},
		{
			name:   "ftp type of git origin url",
			input:  "ftp://host.xz:1234/path/to/repo.git/",
			output: &url.URL{Scheme: "ftp", Host: "host.xz:1234", Path: "/path/to/repo.git/"},
		},
		{
			name:   "ftps type of git origin url",
			input:  "ftps://host.xz/path/to/repo.git/",
			output: &url.URL{Scheme: "ftps", Host: "host.xz", Path: "/path/to/repo.git/"},
		},
		{
			name:   "file:// type of git origin url",
			input:  "file:///path/to/repo.git/",
			output: &url.URL{Scheme: "file", Path: "/path/to/repo.git/"},
		},
		{
			name:   "file path type of git origin url",
			input:  "/path/to/repo.git/",
			output: &url.URL{Scheme: "file", Path: "/path/to/repo.git/"},
		},
		{
			name:   "rsync:// type of git origin url",
			input:  "rsync://host.xz/path/to/repo.git/",
			output: &url.URL{Scheme: "rsync", Host: "host.xz", Path: "/path/to/repo.git/"},
		},
		{
			name:   "git+ssh:// type of git origin url",
			input:  "git+ssh://host.xz/path/to/repo.git/",
			output: &url.URL{Scheme: "git+ssh", Host: "host.xz", Path: "/path/to/repo.git/"},
		},
		{
			name:   "user@host/path of git origin url",
			input:  "user-1@host.xz:path/to/repo.git/",
			output: &url.URL{Scheme: "ssh", Host: "host.xz", Path: "path/to/repo.git/", User: url.User("user-1")},
		},
		{
			name:   "user password url",
			input:  "https://u:p@host.xz/organization/repo.git?ref=test",
			output: &url.URL{Scheme: "https", Host: "host.xz", Path: "/organization/repo.git", RawQuery: "ref=test", User: url.UserPassword("u", "p")},
		},
		{
			name:   "invalid git origin url",
			input:  "some_invalid_string",
			output: &url.URL{Scheme: "file", Path: "some_invalid_string"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := ParseUrl(test.input)
			require.Equal(t, test.output, result)
		})
	}
}
