package processor_test

import (
	"context"
	"errors"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-iac/internal/engine"
	"github.com/snyk/cli-extension-iac/internal/platform"
	"github.com/snyk/cli-extension-iac/internal/processor"
	"github.com/snyk/cli-extension-iac/internal/results"
	"github.com/snyk/cli-extension-iac/internal/settings"
	"github.com/snyk/policy-engine/pkg/models"
)

type mockSnykPlatform struct {
	shareResults         func(ctx context.Context, engineResults *engine.Results, opts platform.ShareResultsOptions) (*platform.ShareResultsOutput, error)
	shareResultsRegistry func(ctx context.Context, engineResults *results.Results, opts platform.ShareResultsOptions, policyFile string) (*platform.ShareResultsOutput, error)
}

func (p mockSnykPlatform) ShareResults(ctx context.Context, engineResults *engine.Results, opts platform.ShareResultsOptions) (*platform.ShareResultsOutput, error) {
	return p.shareResults(ctx, engineResults, opts)
}

func (p mockSnykPlatform) ShareResultsRegistry(ctx context.Context, engineResults *results.Results, opts platform.ShareResultsOptions, policyFile string) (*platform.ShareResultsOutput, error) {
	return p.shareResultsRegistry(ctx, engineResults, opts, policyFile)
}

type mockSettingsReader struct {
	readSettings func(ctx context.Context) (*settings.Settings, error)
}

func (m mockSettingsReader) ReadSettings(ctx context.Context) (*settings.Settings, error) {
	return m.readSettings(ctx)
}

func TestWithoutShareResults(t *testing.T) {
	isShareResultsCalled := false

	snykPlatform := mockSnykPlatform{
		shareResults: func(ctx context.Context, engineResults *engine.Results, opts platform.ShareResultsOptions) (*platform.ShareResultsOutput, error) {
			isShareResultsCalled = true
			return &platform.ShareResultsOutput{URL: "test-url"}, nil
		},
	}

	settingsReader := mockSettingsReader{
		readSettings: func(ctx context.Context) (*settings.Settings, error) {
			return &settings.Settings{}, nil
		},
	}

	resultsProcessor := processor.ResultsProcessor{
		SnykPlatform:   snykPlatform,
		Report:         false,
		GetWd:          func() (string, error) { return "dir/sub-dir", nil },
		GetRepoRootDir: func(string) (string, error) { return "dir", nil },
		SettingsReader: settingsReader,
	}

	results, err := resultsProcessor.ProcessResults(&engine.Results{}, results.ScanAnalytics{})

	require.NoError(t, err)
	require.NotNil(t, results)
	require.False(t, isShareResultsCalled)
}

func TestWithShareResultsSuccess(t *testing.T) {
	isShareResultsCalled := false
	logger := zerolog.Nop()

	snykPlatform := mockSnykPlatform{
		shareResults: func(ctx context.Context, engineResults *engine.Results, opts platform.ShareResultsOptions) (*platform.ShareResultsOutput, error) {
			isShareResultsCalled = true
			return &platform.ShareResultsOutput{URL: "test-url"}, nil
		},
	}

	settingsReader := mockSettingsReader{
		readSettings: func(ctx context.Context) (*settings.Settings, error) {
			return &settings.Settings{}, nil
		},
	}

	resultsProcessor := processor.ResultsProcessor{
		SnykPlatform:           snykPlatform,
		Report:                 true,
		GetWd:                  func() (string, error) { return "dir/sub-dir", nil },
		GetRepoRootDir:         func(string) (string, error) { return "dir", nil },
		GetOriginUrl:           func(string) (string, error) { return "http://host.xz/path/to/repo.git", nil },
		SerializeEngineResults: func(results *engine.Results) (string, error) { return "test-serialized-results", nil },
		SettingsReader:         settingsReader,
		Logger:                 &logger,
	}

	results, err := resultsProcessor.ProcessResults(&engine.Results{
		Results: []models.Result{
			{
				Input: models.State{
					Resources: map[string]map[string]models.ResourceState{
						"aws_instance": {
							"instance": {
								Attributes: map[string]interface{}{
									"ami": "ami-123456",
								},
							},
						},
					},
				},
			},
		},
	}, results.ScanAnalytics{})

	require.NoError(t, err)
	require.NotNil(t, results)
	require.True(t, isShareResultsCalled)
}

func TestWithShareResultsFailure(t *testing.T) {
	logger := zerolog.Nop()
	snykPlatform := mockSnykPlatform{
		shareResults: func(ctx context.Context, engineResults *engine.Results, opts platform.ShareResultsOptions) (*platform.ShareResultsOutput, error) {
			return nil, errors.New("error")
		},
	}

	settingsReader := mockSettingsReader{
		readSettings: func(ctx context.Context) (*settings.Settings, error) {
			return &settings.Settings{}, nil
		},
	}

	resultsProcessor := processor.ResultsProcessor{
		SnykPlatform:           snykPlatform,
		Report:                 true,
		GetWd:                  func() (string, error) { return "dir/sub-dir", nil },
		GetRepoRootDir:         func(string) (string, error) { return "dir", nil },
		GetOriginUrl:           func(string) (string, error) { return "http://host.xz/path/to/repo.git", nil },
		SerializeEngineResults: func(results *engine.Results) (string, error) { return "", errors.New("error") },
		SettingsReader:         settingsReader,
		Logger:                 &logger,
	}

	results, err := resultsProcessor.ProcessResults(&engine.Results{}, results.ScanAnalytics{})

	require.Error(t, err)
	require.Nil(t, results)
}

func TestWithShareResultsRegistrySuccess(t *testing.T) {
	logger := zerolog.Nop()
	isShareResultsCalled := false

	snykPlatform := mockSnykPlatform{
		shareResultsRegistry: func(ctx context.Context, engineResults *results.Results, opts platform.ShareResultsOptions, policyFile string) (*platform.ShareResultsOutput, error) {
			isShareResultsCalled = true
			return &platform.ShareResultsOutput{URL: "test-url", ProjectIds: map[string]string{"Infrastructure_as_code_issues": "test_id"}}, nil
		},
	}

	settingsReader := mockSettingsReader{
		readSettings: func(ctx context.Context) (*settings.Settings, error) {
			return &settings.Settings{}, nil
		},
	}

	resultsProcessor := processor.ResultsProcessor{
		SnykPlatform:           snykPlatform,
		Report:                 true,
		GetWd:                  func() (string, error) { return "dir/sub-dir", nil },
		GetRepoRootDir:         func(string) (string, error) { return "dir", nil },
		GetOriginUrl:           func(string) (string, error) { return "http://host.xz/path/to/repo.git", nil },
		SerializeEngineResults: func(results *engine.Results) (string, error) { return "test-serialized-results", nil },
		SettingsReader:         settingsReader,
		IacNewEngine:           true,
		Logger:                 &logger,
	}

	results, err := resultsProcessor.ProcessResults(&engine.Results{
		Results: []models.Result{
			{
				Input: models.State{
					Resources: map[string]map[string]models.ResourceState{
						"aws_instance": {
							"instance": {
								Attributes: map[string]interface{}{
									"ami": "ami-123456",
								},
							},
						},
					},
				},
			},
		},
	}, results.ScanAnalytics{})

	require.NoError(t, err)
	require.NotNil(t, results)
	assert.Equal(t, "test_id", results.Metadata.ProjectPublicId)
	require.True(t, isShareResultsCalled)
}

func TestWithShareResultsRegistryFailure(t *testing.T) {
	logger := zerolog.Nop()
	snykPlatform := mockSnykPlatform{
		shareResultsRegistry: func(ctx context.Context, engineResults *results.Results, opts platform.ShareResultsOptions, policyFile string) (*platform.ShareResultsOutput, error) {
			return nil, errors.New("error")
		},
	}

	settingsReader := mockSettingsReader{
		readSettings: func(ctx context.Context) (*settings.Settings, error) {
			return &settings.Settings{}, nil
		},
	}

	resultsProcessor := processor.ResultsProcessor{
		SnykPlatform:           snykPlatform,
		Report:                 true,
		GetWd:                  func() (string, error) { return "dir/sub-dir", nil },
		GetRepoRootDir:         func(string) (string, error) { return "dir", nil },
		GetOriginUrl:           func(string) (string, error) { return "http://host.xz/path/to/repo.git", nil },
		SerializeEngineResults: func(results *engine.Results) (string, error) { return "", errors.New("error") },
		SettingsReader:         settingsReader,
		IacNewEngine:           true,
		Logger:                 &logger,
	}

	results, err := resultsProcessor.ProcessResults(&engine.Results{}, results.ScanAnalytics{})

	require.Error(t, err)
	require.Nil(t, results)
}
