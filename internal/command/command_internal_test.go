//nolint:testpackage
package command

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExclusion_MultiRoot(t *testing.T) {
	logger := zerolog.Nop()
	files := map[string]string{
		"proj1/keep.tf":            "content",
		"proj1/exclude_me/file.tf": "content", // Drop
		"proj2/exclude_me/file.tf": "content", // Drop
	}
	tmpDir := setupTempDir(t, files)

	root1 := filepath.Join(tmpDir, "proj1")
	root2 := filepath.Join(tmpDir, "proj2")

	cmd := Command{
		FS:      afero.NewOsFs(),
		Logger:  &logger,
		Exclude: []string{"exclude_me"},
	}

	results, err := cmd.applyExclusions([]string{root1, root2})
	require.NoError(t, err)

	assert.Len(t, results, 1)
	assert.True(t, strings.HasSuffix(filepath.ToSlash(results[0]), "proj1/keep.tf"))
}

func TestExclusion_FileVsDir(t *testing.T) {
	logger := zerolog.Nop()
	files := map[string]string{
		"workdir/keep.tf":   "content",
		"workdir/ignore.tf": "content",
	}
	tmpDir := setupTempDir(t, files)
	root := filepath.Join(tmpDir, "workdir")

	cmd := Command{
		FS:      afero.NewOsFs(),
		Logger:  &logger,
		Exclude: []string{"ignore.tf"},
	}

	results, err := cmd.applyExclusions([]string{root})
	require.NoError(t, err)

	require.Len(t, results, 1)
	assert.True(t, strings.HasSuffix(filepath.ToSlash(results[0]), "keep.tf"))
}

func Test_buildExclusionGlobs(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expected      []string
		expectedError bool
	}{
		{
			name:     "Empty input returns empty slice",
			input:    "",
			expected: []string{},
		},
		{
			name:  "Standard directory and file",
			input: "node_modules,config.json",
			expected: []string{
				"**/node_modules", "**/node_modules/**",
				"**/config.json", "**/config.json/**",
			},
		},
		{
			name:  "Noisy whitespace and empty entries",
			input: "  item1 , , item2  ",
			expected: []string{
				"**/item1", "**/item1/**",
				"**/item2", "**/item2/**",
			},
		},
		{
			name:          "Slash in input returns error",
			input:         "dir/subdir",
			expectedError: true,
		},
		{
			name:          "Windows backslash returns error",
			input:         "target\\debug",
			expectedError: true,
		},
		{
			name:          "Path traversal returns error",
			input:         "../etc",
			expectedError: true,
		},
		{
			name:     "Hidden files work without slashes",
			input:    ".env",
			expected: []string{"**/.env", "**/.env/**"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildExclusionGlobs(tt.input)
			if tt.expectedError {
				assert.Error(t, err)
				assert.Nil(t, got)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, got)
			}
		})
	}
}

func setupTempDir(t *testing.T, files map[string]string) string {
	t.Helper()
	tmpDir := t.TempDir()
	canonicalPath, _ := filepath.EvalSymlinks(tmpDir)

	for path, content := range files {
		fullPath := filepath.Join(canonicalPath, path)
		_ = os.MkdirAll(filepath.Dir(fullPath), 0o755)
		_ = os.WriteFile(fullPath, []byte(content), 0o600)
	}
	return canonicalPath
}
