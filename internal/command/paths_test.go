package command

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/snyk/cli-extension-iac/internal/cloudapi"
	"github.com/snyk/cli-extension-iac/internal/engine"
	"github.com/snyk/cli-extension-iac/internal/results"
	"github.com/snyk/cli-extension-iac/internal/settings"
	"github.com/snyk/policy-engine/pkg/bundle"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockEngine struct {
	run func(ctx context.Context, options engine.RunOptions) (*engine.Results, results.ScanAnalytics, []error, []error)
}

func (e mockEngine) Run(ctx context.Context, options engine.RunOptions) (*engine.Results, results.ScanAnalytics, []error, []error) {
	return e.run(ctx, options)
}

type mockResultsProcessor struct {
	processResults func(rawResults *engine.Results, scanAnalytics results.ScanAnalytics) (*results.Results, error)
}

func (m mockResultsProcessor) ProcessResults(rawResults *engine.Results, scanAnalytics results.ScanAnalytics) (*results.Results, error) {
	return m.processResults(rawResults, scanAnalytics)
}

type readSettingsFunc func(ctx context.Context) (*settings.Settings, error)

func (f readSettingsFunc) ReadSettings(ctx context.Context) (*settings.Settings, error) {
	return f(ctx)
}

type downloadBundleFunc func(peVersion string, w io.Writer) error

func (f downloadBundleFunc) DownloadLatestBundle(peVersion string, w io.Writer) error {
	return f(peVersion, w)
}

type mockCloudApiClient struct {
	customRules  func(ctx context.Context, orgID string) (readers []bundle.Reader, e error)
	createScan   func(ctx context.Context, orgID string, request *cloudapi.CreateScanRequest, useInternalEndpoint bool) (*cloudapi.CreateScanResponse, error)
	environments func(ctx context.Context, orgID, snykCloudEnvironmentID string) (envs []cloudapi.EnvironmentObject, e error)
	resources    func(ctx context.Context, orgID, environmentID, resourceType, resourceKind string) (resources []cloudapi.ResourceObject, e error)
}

func (c *mockCloudApiClient) CustomRules(ctx context.Context, orgID string) (readers []bundle.Reader, e error) {
	if c.customRules == nil {
		return nil, nil
	}
	return c.customRules(ctx, orgID)
}

func (c *mockCloudApiClient) CustomRulesInternal(ctx context.Context, orgID string) (readers []bundle.Reader, e error) {
	if c.customRules == nil {
		return nil, nil
	}
	return c.customRules(ctx, orgID)
}

func (c *mockCloudApiClient) CreateScan(ctx context.Context, orgID string, request *cloudapi.CreateScanRequest, useInternalEndpoint bool) (*cloudapi.CreateScanResponse, error) {
	if c.createScan == nil {
		return nil, nil
	}
	return c.createScan(ctx, orgID, request, useInternalEndpoint)
}

func (c *mockCloudApiClient) Environments(ctx context.Context, orgID, snykCloudEnvironmentID string) (envs []cloudapi.EnvironmentObject, e error) {
	if c.environments == nil {
		return nil, nil
	}
	return c.environments(ctx, orgID, snykCloudEnvironmentID)
}

func (c *mockCloudApiClient) Resources(ctx context.Context, orgID, environmentID, resourceType, resourceKind string) (resources []cloudapi.ResourceObject, e error) {
	if c.resources == nil {
		return nil, nil
	}
	return c.resources(ctx, orgID, environmentID, resourceType, resourceKind)
}

var outputFilePath = "test.json"

func TestExcludeFiltering_OSSingleRoot(t *testing.T) {
	logger := zerolog.Nop()

	workspace := t.TempDir()
	withinDir(t, workspace)

	// Create bundle file expected by command
	require.NoError(t, os.WriteFile("bundle.tar.gz", nil, 0644))

	// Create test tree
	require.NoError(t, os.MkdirAll(filepath.Join("root", "a"), 0755))
	require.NoError(t, os.MkdirAll(filepath.Join("root", "b"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join("root", "a", "file1.tf"), []byte(""), 0644))
	require.NoError(t, os.WriteFile(filepath.Join("root", "a", "keep.tf"), []byte(""), 0644))
	require.NoError(t, os.WriteFile(filepath.Join("root", "b", "file2.tf"), []byte(""), 0644))

	capturedPaths := make([]string, 0)
	policyEngine := mockEngine{
		run: func(ctx context.Context, options engine.RunOptions) (*engine.Results, results.ScanAnalytics, []error, []error) {
			capturedPaths = append(capturedPaths, options.Paths...)
			return &engine.Results{}, results.ScanAnalytics{}, nil, nil
		},
	}
	resultsProcessor := mockResultsProcessor{
		processResults: func(rawResults *engine.Results, scanAnalytics results.ScanAnalytics) (*results.Results, error) {
			return &results.Results{}, nil
		},
	}
	userSettings := settings.Settings{Entitlements: settings.Entitlements{InfrastructureAsCode: true}}
	settingsReader := readSettingsFunc(func(ctx context.Context) (*settings.Settings, error) { return &userSettings, nil })

	cmd := Command{
		FS:               afero.NewOsFs(),
		Engine:           policyEngine,
		Paths:            []string{filepath.Join("root")},
		Bundle:           "bundle.tar.gz",
		ResultsProcessor: resultsProcessor,
		SettingsReader:   settingsReader,
		Output:           outputFilePath,
		Logger:           &logger,
		// Only basenames are allowed. Paths like "a/file1.tf" would trigger an error.
		Exclude: []string{"b", "file1.tf"},
	}

	require.Equal(t, 0, cmd.Run())

	// verify keep.tf included, excluded files absent
	norm := normalizeToSlash(capturedPaths)
	require.Contains(t, norm, filepath.ToSlash(filepath.Join("root", "a", "keep.tf")))
	require.NotContains(t, norm, filepath.ToSlash(filepath.Join("root", "b", "file2.tf")))
	require.NotContains(t, norm, filepath.ToSlash(filepath.Join("root", "a", "file1.tf")))
}

func TestExcludeFiltering_OSMultiRoot(t *testing.T) {
	logger := zerolog.Nop()
	workspace := t.TempDir()
	withinDir(t, workspace)
	require.NoError(t, os.WriteFile("bundle.tar.gz", nil, 0644))

	// Create two roots under the same workspace
	for _, root := range []string{"root1", "root2"} {
		require.NoError(t, os.MkdirAll(filepath.Join(root, "keep"), 0755))
		require.NoError(t, os.MkdirAll(filepath.Join(root, "node_modules"), 0755))
		require.NoError(t, os.MkdirAll(filepath.Join(root, ".terraform"), 0755))
		require.NoError(t, os.WriteFile(filepath.Join(root, "keep", "main.tf"), []byte(""), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(root, "node_modules", "ignore.tf"), []byte(""), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(root, ".terraform", "ignore.tf"), []byte(""), 0644))
	}

	capturedPaths := make([]string, 0)
	policyEngine := mockEngine{
		run: func(ctx context.Context, options engine.RunOptions) (*engine.Results, results.ScanAnalytics, []error, []error) {
			capturedPaths = append(capturedPaths, options.Paths...)
			return &engine.Results{}, results.ScanAnalytics{}, nil, nil
		},
	}
	resultsProcessor := mockResultsProcessor{processResults: func(rawResults *engine.Results, scanAnalytics results.ScanAnalytics) (*results.Results, error) {
		return &results.Results{}, nil
	}}
	userSettings := settings.Settings{Entitlements: settings.Entitlements{InfrastructureAsCode: true}}
	settingsReader := readSettingsFunc(func(ctx context.Context) (*settings.Settings, error) { return &userSettings, nil })

	cmd := Command{
		FS:               afero.NewOsFs(),
		Engine:           policyEngine,
		Paths:            []string{"root1", "root2"},
		Bundle:           "bundle.tar.gz",
		ResultsProcessor: resultsProcessor,
		SettingsReader:   settingsReader,
		Output:           outputFilePath,
		Logger:           &logger,
		Exclude:          []string{"node_modules", ".terraform"},
	}

	require.Equal(t, 0, cmd.Run())

	norm := normalizeToSlash(capturedPaths)
	require.Contains(t, norm, filepath.ToSlash(filepath.Join("root1", "keep", "main.tf")))
	require.Contains(t, norm, filepath.ToSlash(filepath.Join("root2", "keep", "main.tf")))
	require.NotContains(t, norm, filepath.ToSlash(filepath.Join("root1", "node_modules", "ignore.tf")))
	require.NotContains(t, norm, filepath.ToSlash(filepath.Join("root2", ".terraform", "ignore.tf")))
}

func TestExcludeFiltering_ErrorOnPaths(t *testing.T) {
	logger := zerolog.Nop()
	workspace := t.TempDir()
	withinDir(t, workspace)
	require.NoError(t, os.MkdirAll("root", 0755))
	require.NoError(t, os.WriteFile("bundle.tar.gz", nil, 0644))

	resultsProcessor := mockResultsProcessor{
		processResults: func(rawResults *engine.Results, scanAnalytics results.ScanAnalytics) (*results.Results, error) {
			return &results.Results{}, nil
		},
	}
	userSettings := settings.Settings{Entitlements: settings.Entitlements{InfrastructureAsCode: true}}
	settingsReader := readSettingsFunc(func(ctx context.Context) (*settings.Settings, error) { return &userSettings, nil })

	cmd := Command{
		FS:               afero.NewOsFs(),
		Paths:            []string{"root"},
		Bundle:           "bundle.tar.gz",
		ResultsProcessor: resultsProcessor,
		SettingsReader:   settingsReader,
		Output:           outputFilePath,
		Logger:           &logger,
		// This will trigger an ErrPathNotAllowed
		Exclude: []string{"a/file1.tf"},
	}

	exitCode := cmd.Run()
	assert.Equal(t, 0, exitCode, "Command should exit with 0 when invalid exclude paths are provided")
	requireError(t, cmd.FS, scanError{
		Message: "the --exclude argument must be a comma separated list of directory or file names and cannot contain a path",
		Code:    2001,
	})
}

func withinDir(t *testing.T, dir string) {
	t.Helper()
	prev, err := os.Getwd()
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Chdir(prev) })
	require.NoError(t, os.Chdir(dir))
}

func normalizeToSlash(in []string) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		out = append(out, filepath.ToSlash(p))
	}
	return out
}

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

func requireError(t *testing.T, fs afero.Fs, expected scanError) {
	t.Helper()

	var output struct {
		Errors []scanError
	}

	readOutput(t, fs, &output)

	require.Contains(t, output.Errors, expected)
}

func readOutput(t *testing.T, fs afero.Fs, output any) {
	t.Helper()

	data, err := afero.ReadFile(fs, outputFilePath)
	require.NoError(t, err)

	require.NoError(t, json.Unmarshal(data, output))
}
