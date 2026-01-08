package command_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-iac/internal/command"
	"github.com/snyk/cli-extension-iac/internal/engine"
	"github.com/snyk/cli-extension-iac/internal/results"
	"github.com/snyk/cli-extension-iac/internal/settings"
)

// Reuse mock types from command_test.go

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

	cmd := command.Command{
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

	cmd := command.Command{
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

	cmd := command.Command{
		FS:               afero.NewOsFs(),
		Paths:            []string{"root"},
		Bundle:           "bundle.tar.gz",
		ResultsProcessor: resultsProcessor,
		SettingsReader:   settingsReader,
		Logger:           &logger,
		// This will trigger an ErrPathNotAllowed
		Exclude: []string{"a/file1.tf"},
	}

	exitCode := cmd.Run()
	assert.Equal(t, 1, exitCode, "Command should exit with 1 when invalid exclude paths are provided")
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
