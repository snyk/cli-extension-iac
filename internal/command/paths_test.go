package command

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizePaths(t *testing.T) {
	tests := []struct {
		name   string
		cwd    string
		input  string
		output string
	}{
		{
			name:   "original cwd original path",
			cwd:    filepath.Join("testdata", "symlinks", "original"),
			input:  filepath.Join("testdata", "symlinks", "original"),
			output: ".",
		},
		{
			name:   "original cwd linked path",
			cwd:    filepath.Join("testdata", "symlinks", "original"),
			input:  filepath.Join("testdata", "symlinks", "linked"),
			output: filepath.Join("..", "linked"),
		},
		{
			name:   "linked cwd linked path",
			cwd:    filepath.Join("testdata", "symlinks", "linked"),
			input:  filepath.Join("testdata", "symlinks", "linked"),
			output: ".",
		},
		{
			name:   "linked cwd original path",
			cwd:    filepath.Join("testdata", "symlinks", "linked"),
			input:  filepath.Join("testdata", "symlinks", "original"),
			output: filepath.Join("..", "original"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// symlinks are not a thing on windows
			if runtime.GOOS == "windows" && strings.Contains(test.name, "linked") {
				t.Skip("skipping on windows")
			}
			input, err := filepath.Abs(test.input)
			if err != nil {
				t.Fatal(err)
			}

			cwd, err := filepath.Abs(test.cwd)
			if err != nil {
				t.Fatal(err)
			}

			withCurrentWorkingDirectory(t, cwd)
			withEnvironmentVariable(t, "PWD", cwd)

			paths, err := normalizePaths([]string{input})
			if err != nil {
				t.Fatal(err)
			}

			if v := paths[0]; v != test.output {
				t.Fatalf("unexpcted path: want %v, expected %v", test.output, v)
			}
		})
	}
}

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

	cwd, _ := os.Getwd()
	results, err := applyExclusions([]string{"exclude_me"}, afero.NewOsFs(), &logger, []string{root1, root2}, cwd)
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

	cwd, _ := os.Getwd()
	results, err := applyExclusions([]string{"ignore.tf"}, afero.NewOsFs(), &logger, []string{root}, cwd)
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

func Test_applyExclusions(t *testing.T) {
	logger := zerolog.Nop()
	fs := afero.NewOsFs()

	files := map[string]string{
		"README.md":                 "content",
		"file2":                     "content",
		"src/main.go":               "content",
		"src/file2":                 "content",
		"src/ignore_dir/data.txt":   "content",
		"src/keep_dir/file2":        "content",
		"src/keep_dir/valuable.txt": "content",
		"libs/ignore_dir/lib.so":    "content",
	}

	tmpDir := setupTempDir(t, files)
	tests := []struct {
		name          string
		inputPaths    []string
		excludeRules  []string
		expectedPaths []string
		expectError   bool
	}{
		{
			name:         "Exclude Directory Name Recursively",
			inputPaths:   []string{"."},
			excludeRules: []string{"ignore_dir"},
			expectedPaths: []string{
				"README.md",
				"file2",
				"src/main.go",
				"src/file2",
				"src/keep_dir/file2",
				"src/keep_dir/valuable.txt",
			},
		},
		{
			name:         "Exclude File Name Recursively",
			inputPaths:   []string{"."},
			excludeRules: []string{"file2"},
			expectedPaths: []string{
				"README.md",
				"src/main.go",
				"src/ignore_dir/data.txt",
				"src/keep_dir/valuable.txt",
				"libs/ignore_dir/lib.so",
			},
		},
		{
			name:         "Exclude Multiple Names",
			inputPaths:   []string{"."},
			excludeRules: []string{"file2", "ignore_dir"},
			expectedPaths: []string{
				"README.md",
				"src/main.go",
				"src/keep_dir/valuable.txt",
			},
		},
		{
			name:         "Exclude Invalid Path (Error)",
			inputPaths:   []string{"."},
			excludeRules: []string{"src/ignore_dir"},
			expectError:  true,
		},
		{
			name:         "Specific Input Path with Exclusion",
			inputPaths:   []string{"src/keep_dir"},
			excludeRules: []string{"file2"},
			expectedPaths: []string{
				"src/keep_dir/valuable.txt",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Resolve input paths to absolute
			var absInputs []string
			for _, p := range tt.inputPaths {
				absInputs = append(absInputs, filepath.Join(tmpDir, p))
			}

			got, err := applyExclusions(tt.excludeRules, fs, &logger, absInputs, tmpDir)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				// Normalize OS separators for assertions
				var normalizedExpected []string
				for _, p := range tt.expectedPaths {
					normalizedExpected = append(normalizedExpected, filepath.FromSlash(p))
				}
				assert.ElementsMatch(t, normalizedExpected, got)
			}
		})
	}
}

func Test_HelperFunctions(t *testing.T) {
	t.Run("resolveAbs", func(t *testing.T) {
		abs, _ := filepath.Abs(".")
		assert.Equal(t, abs, resolveAbs(abs))

		rel := "foo/bar"
		resolved := resolveAbs(rel)
		assert.True(t, filepath.IsAbs(resolved), "Expected relative path to become absolute")
		assert.Contains(t, resolved, filepath.Clean(rel))
	})

	t.Run("deduplicatePaths", func(t *testing.T) {
		input := []string{"a", "b", "a", "c", "b"}
		expected := []string{"a", "b", "c"}
		assert.Equal(t, expected, deduplicatePaths(input))

		assert.Empty(t, deduplicatePaths([]string{}))
	})

	t.Run("makeRelative", func(t *testing.T) {
		cwd := filepath.FromSlash("/user/project")
		inputPath := filepath.FromSlash("/user/project/src/main.go")

		// Happy path
		assert.Equal(t, filepath.FromSlash("src/main.go"), makeRelative(inputPath, cwd))
		// Fallback path
		unrelated := filepath.FromSlash("/etc/hosts")
		assert.NotEmpty(t, makeRelative(unrelated, cwd))
	})
}

func withCurrentWorkingDirectory(t *testing.T, cwd string) {
	t.Helper()

	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		if err := os.Chdir(prev); err != nil {
			t.Fatal(err)
		}
	})

	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}
}

func withEnvironmentVariable(t *testing.T, name, value string) {
	prev := os.Getenv("PWD")

	t.Cleanup(func() {
		if err := os.Setenv(name, prev); err != nil {
			t.Fatal(err)
		}
	})

	if err := os.Setenv(name, value); err != nil {
		t.Fatal(err)
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
