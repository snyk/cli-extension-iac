package processor

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestComputeProjectName(t *testing.T) {
	tests := []struct {
		name      string
		processor ResultsProcessor
		output    string
	}{
		{
			name: "cwd and root repo dir matching",
			processor: ResultsProcessor{
				GetWd:          func() (string, error) { return "dir/sub-dir", nil },
				GetRepoRootDir: func(string) (string, error) { return "dir/sub-dir", nil },
				GetOriginUrl:   func(string) (string, error) { return "git@github.com:snyk/cli-extension-iac.git", nil },
			},
			output: "snyk/cli-extension-iac",
		},
		{
			name: "cwd and root repo dir not matching",
			processor: ResultsProcessor{
				GetWd:          func() (string, error) { return "dir/sub-dir", nil },
				GetRepoRootDir: func(string) (string, error) { return "dir", nil },
				GetOriginUrl:   func(string) (string, error) { return "git@github.com:snyk/cli-extension-iac.git", nil },
			},
			output: "sub-dir",
		},
		{
			name: "target-name is set",
			processor: ResultsProcessor{
				GetWd:          func() (string, error) { return "dir/sub-dir", nil },
				GetRepoRootDir: func(string) (string, error) { return "dir", nil },
				GetOriginUrl:   func(string) (string, error) { return "git@github.com:snyk/cli-extension-iac.git", nil },
				TargetName:     "Target Name",
			},
			output: "Target Name",
		},
		{
			name: "remote-repo-url is set",
			processor: ResultsProcessor{
				GetWd:          func() (string, error) { return "dir/sub-dir", nil },
				GetRepoRootDir: func(string) (string, error) { return "dir", nil },
				GetOriginUrl:   func(string) (string, error) { return "git@github.com:snyk/cli-extension-iac.git", nil },
				RemoteRepoUrl:  "git@github.com:test/remote-repo-url.git",
			},
			output: "test/remote-repo-url",
		},
		{
			name: "target-name and remote-repo-url are set",
			processor: ResultsProcessor{
				GetWd:          func() (string, error) { return "dir/sub-dir", nil },
				GetRepoRootDir: func(string) (string, error) { return "dir", nil },
				GetOriginUrl:   func(string) (string, error) { return "git@github.com:snyk/cli-extension-iac.git", nil },
				TargetName:     "Target Name",
				RemoteRepoUrl:  "git@github.com:test/remote-repo-url.git",
			},
			output: "Target Name",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, _ := test.processor.computeProjectName()
			require.Equal(t, test.output, result)
		})
	}
}

func TestGetProjectNameFromGitOriginUrl(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		output string
	}{
		{
			name:   "user@host type of git origin url",
			input:  "user@host.xz:path/to/repo.git/",
			output: "path/to/repo",
		},
		{
			name:   "host:path type of git origin url",
			input:  "host.xz:/path/to/repo.git/",
			output: "path/to/repo",
		},
		{
			name:   "git:// type of git origin url",
			input:  "git://host.xz/path/to/repo.git/",
			output: "path/to/repo",
		},
		{
			name:   "http git origin url",
			input:  "http://host.xz/path/to/repo.git/",
			output: "path/to/repo",
		},
		{
			name:   "https git origin url",
			input:  "https://host.xz:1234/path/to/repo.git/",
			output: "path/to/repo",
		},
		{
			name:   "git@ type of git origin url",
			input:  "git@host.xz:path/to/repo.git?ref=test",
			output: "path/to/repo",
		},
		{
			name:   "ssh type of git origin url",
			input:  "ssh://host.xz:1234/path/to/repo.git/",
			output: "path/to/repo",
		},
		{
			name:   "ftp type of git origin url",
			input:  "ftp://host.xz:1234/path/to/repo.git/",
			output: "path/to/repo",
		},
		{
			name:   "ftps type of git origin url",
			input:  "ftps://host.xz/path/to/repo.git/",
			output: "path/to/repo",
		},
		{
			name:   "file:// type of git origin url",
			input:  "file:///path/to/repo.git/",
			output: "path/to/repo",
		},
		{
			name:   "file path type of git origin url",
			input:  "/path/to/repo.git/",
			output: "path/to/repo",
		},
		{
			name:   "rsync:// type of git origin url",
			input:  "rsync://host.xz/path/to/repo.git/",
			output: "path/to/repo",
		},
		{
			name:   "git+ssh:// type of git origin url",
			input:  "git+ssh://host.xz/path/to/repo.git/",
			output: "path/to/repo",
		},
		{
			name:   "Azure DevOps Git URL",
			input:  "https://example.com/organization/project/_git/repository",
			output: "organization/project/repository",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output, err := getProjectNameFromGitOriginUrl(test.input)
			require.NoError(t, err)
			require.Equal(t, test.output, output)
		})
	}
}
