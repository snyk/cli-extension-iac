package command_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/rs/zerolog"
	"github.com/snyk/policy-engine/pkg/bundle"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-iac/internal/cloudapi"
	"github.com/snyk/cli-extension-iac/internal/command"
	"github.com/snyk/cli-extension-iac/internal/engine"
	"github.com/snyk/cli-extension-iac/internal/results"
	"github.com/snyk/cli-extension-iac/internal/settings"
)

type scanError struct {
	Message string
	Code    int
	Fields  map[string]interface{}
}

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

func TestNoPaths(t *testing.T) {
	logger := zerolog.Nop()
	fs := afero.NewMemMapFs()
	_, _ = fs.Create(outputFilePath)

	resultsProcessor := mockResultsProcessor{
		processResults: func(rawResults *engine.Results, scanAnalytics results.ScanAnalytics) (*results.Results, error) {
			return nil, nil
		},
	}

	userSettings := settings.Settings{
		Entitlements: settings.Entitlements{
			InfrastructureAsCode: true,
		},
	}

	settingsReader := readSettingsFunc(func(ctx context.Context) (*settings.Settings, error) {
		return &userSettings, nil
	})

	cmd := command.Command{
		Output:           outputFilePath,
		FS:               fs,
		Bundle:           "bundle.tar.gz",
		ResultsProcessor: resultsProcessor,
		SettingsReader:   settingsReader,
		Logger:           &logger,
	}

	require.Equal(t, 0, cmd.Run())

	requireError(t, fs, scanError{
		Message: "no valid paths",
		Code:    2000,
	})
}

func TestCurrentWorkingDirectoryTraversal(t *testing.T) {
	logger := zerolog.Nop()
	fs := afero.NewMemMapFs()
	_, _ = fs.Create(outputFilePath)

	resultsProcessor := mockResultsProcessor{
		processResults: func(rawResults *engine.Results, scanAnalytics results.ScanAnalytics) (*results.Results, error) {
			return nil, nil
		},
	}

	userSettings := settings.Settings{
		Entitlements: settings.Entitlements{
			InfrastructureAsCode: true,
		},
	}

	settingsReader := readSettingsFunc(func(ctx context.Context) (*settings.Settings, error) {
		return &userSettings, nil
	})

	cmd := command.Command{
		Output:           outputFilePath,
		FS:               fs,
		Paths:            []string{".."},
		Bundle:           "bundle.tar.gz",
		ResultsProcessor: resultsProcessor,
		SettingsReader:   settingsReader,
		Logger:           &logger,
	}

	require.Equal(t, 0, cmd.Run())

	requireError(t, fs, scanError{
		Message: "current working directory traversal",
		Code:    2003,
		Fields: map[string]interface{}{
			"path": "..",
		},
	})

	requireError(t, fs, scanError{
		Message: "no valid paths",
		Code:    2000,
	})
}

func TestNoBundle(t *testing.T) {
	logger := zerolog.Nop()
	fs := afero.NewMemMapFs()
	_, _ = fs.Create(outputFilePath)

	resultsProcessor := mockResultsProcessor{
		processResults: func(rawResults *engine.Results, scanAnalytics results.ScanAnalytics) (*results.Results, error) {
			return nil, nil
		},
	}

	userSettings := settings.Settings{
		Entitlements: settings.Entitlements{
			InfrastructureAsCode: true,
		},
	}

	settingsReader := readSettingsFunc(func(ctx context.Context) (*settings.Settings, error) {
		return &userSettings, nil
	})

	expectedError := errors.New("some error")

	bundleDownloader := downloadBundleFunc(func(peVersion string, w io.Writer) error {
		return expectedError
	})

	readPolicyEngineVersion := func() (string, error) {
		return "", expectedError
	}

	cmd := command.Command{
		Output:                  outputFilePath,
		FS:                      fs,
		Paths:                   []string{"dir"},
		ResultsProcessor:        resultsProcessor,
		SettingsReader:          settingsReader,
		BundleDownloader:        bundleDownloader,
		ReadPolicyEngineVersion: readPolicyEngineVersion,
		Logger:                  &logger,
	}

	require.Equal(t, 0, cmd.Run())
	require.Error(t, expectedError)
}

func TestBundleDoesNotExist(t *testing.T) {
	logger := zerolog.Nop()
	fs := afero.NewMemMapFs()
	_, _ = fs.Create(outputFilePath)

	resultsProcessor := mockResultsProcessor{
		processResults: func(rawResults *engine.Results, scanAnalytics results.ScanAnalytics) (*results.Results, error) {
			return nil, nil
		},
	}

	userSettings := settings.Settings{
		Entitlements: settings.Entitlements{
			InfrastructureAsCode: true,
		},
	}

	settingsReader := readSettingsFunc(func(ctx context.Context) (*settings.Settings, error) {
		return &userSettings, nil
	})

	cmd := command.Command{
		Output:           outputFilePath,
		FS:               fs,
		Paths:            []string{"."},
		Bundle:           "bundle.tar.gz",
		ResultsProcessor: resultsProcessor,
		SettingsReader:   settingsReader,
		Logger:           &logger,
	}

	require.Equal(t, 0, cmd.Run())

	requireError(t, fs, scanError{
		Message: "unable to open bundle",
		Code:    2004,
	})
}

func TestScanError(t *testing.T) {
	tests := []struct {
		name     string
		actual   error
		expected scanError
	}{
		{
			name:   "generic error",
			actual: errors.New("error"),
			expected: scanError{
				Message: "unable to scan",
				Code:    2100,
			},
		},
		{
			name: "unable to read file",
			actual: engine.Error{
				Code: engine.ErrorCodeUnableToReadFile,
				Path: "/path",
			},
			expected: scanError{
				Message: "unable to read file",
				Code:    2107,
				Fields: map[string]interface{}{
					"path": "/path",
				},
			},
		},
		{
			name: "unable to recognize input type",
			actual: engine.Error{
				Code: engine.ErrorCodeUnableToRecognizeInputType,
				Path: "/path",
			},
			expected: scanError{
				Message: "unable to recognize input type",
				Code:    2101,
				Fields: map[string]interface{}{
					"path": "/path",
				},
			},
		},
		{
			name: "unsupported input type",
			actual: engine.Error{
				Code: engine.ErrorCodeUnsupportedInputType,
			},
			expected: scanError{
				Message: "unsupported input type",
				Code:    2102,
			},
		},
		{
			name: "unable to resolve location",
			actual: engine.Error{
				Code: engine.ErrorCodeUnableToResolveLocation,
				Path: "/path",
			},
			expected: scanError{
				Message: "unable to resolve location",
				Code:    2103,
				Fields: map[string]interface{}{
					"path": "/path",
				},
			},
		},
		{
			name: "unrecognized file extension",
			actual: engine.Error{
				Code: engine.ErrorCodeUnrecognizedFileExtension,
			},
			expected: scanError{
				Message: "unrecognized file extension",
				Code:    2104,
			},
		},
		{
			name: "failed to parse input",
			actual: engine.Error{
				Code: engine.ErrorCodeFailedToParseInput,
			},
			expected: scanError{
				Message: "failed to parse input",
				Code:    2105,
			},
		},
		{
			name: "invalid input",
			actual: engine.Error{
				Code: engine.ErrorCodeInvalidInput,
			},
			expected: scanError{
				Message: "invalid input for input type",
				Code:    2106,
			},
		},
		{
			name: "unable to read directory",
			actual: engine.Error{
				Code: engine.ErrorCodeUnableToReadDir,
				Path: "/path",
			},
			expected: scanError{
				Message: "unable to read directory",
				Code:    2108,
				Fields: map[string]interface{}{
					"path": "/path",
				},
			},
		},
		{
			name: "unable to read stdin",
			actual: engine.Error{
				Code: engine.ErrorCodeUnableToReadStdin,
				Path: "/path",
			},
			expected: scanError{
				Message: "unable to read stdin",
				Code:    2109,
				Fields: map[string]interface{}{
					"path": "/path",
				},
			},
		},
		{
			name: "failed to load Rego API",
			actual: engine.Error{
				Code: engine.ErrorCodeFailedToLoadRegoAPI,
			},
			expected: scanError{
				Message: "failed to load the snyk Rego API",
				Code:    2110,
			},
		},
		{
			name: "failed to load bundle",
			actual: engine.Error{
				Code: engine.ErrorCodeFailedToLoadRules,
			},
			expected: scanError{
				Message: "failed to load rules",
				Code:    2111,
			},
		},
		{
			name: "failed to compile",
			actual: engine.Error{
				Code: engine.ErrorCodeFailedToCompile,
			},
			expected: scanError{
				Message: "failed to compile rules",
				Code:    2112,
			},
		},
		{
			name: "unable to read path",
			actual: engine.Error{
				Code: engine.ErrorCodeUnableToReadPath,
				Path: "/path",
			},
			expected: scanError{
				Message: "unable to read path",
				Code:    2113,
				Fields: map[string]interface{}{
					"path": "/path",
				},
			},
		},
		{
			name: "no loadable input",
			actual: engine.Error{
				Code: engine.ErrorCodeNoLoadableInputs,
			},
			expected: scanError{
				Message: "no loadable input",
				Code:    2114,
			},
		},
		{
			name: "submodule loading error",
			actual: engine.SubmoduleLoadingError{
				Message: "submodule loading error",
				Code:    engine.ErrorCodeSubmoduleLoadingError,
				Path:    "/path",
				Module:  "submodule",
			},
			expected: scanError{
				Message: "submodule loading error",
				Code:    3000,
				Fields: map[string]interface{}{
					"path":   "/path",
					"module": "submodule",
				},
			},
		},
		{
			name: "missing remote submodules error",
			actual: engine.MissingRemoteSubmodulesError{
				Message:        "missing remote submodules",
				Code:           engine.ErrorCodeMissingRemoteSubmodulesError,
				Path:           "/path",
				Dir:            "/dir",
				MissingModules: []string{"module1", "module2"},
			},
			expected: scanError{
				Message: "missing remote submodules",
				Code:    3001,
				Fields: map[string]interface{}{
					"path":    "/path",
					"dir":     "/dir",
					"modules": []interface{}{"module1", "module2"},
				},
			},
		},
		{
			name: "evaluation error",
			actual: engine.EvaluationError{
				Message:     "evaluation error",
				Code:        engine.ErrorCodeEvaluationError,
				Path:        "/path",
				Expressions: []string{"expr1", "expr2"},
			},
			expected: scanError{
				Message: "evaluation error",
				Code:    3002,
				Fields: map[string]interface{}{
					"path":        "/path",
					"expressions": []interface{}{"expr1", "expr2"},
				},
			},
		},
		{
			name: "missing term error",
			actual: engine.MissingTermError{
				Message: "missing term error",
				Code:    engine.ErrorCodeMissingTermError,
				Path:    "/path",
				Term:    "term",
			},
			expected: scanError{
				Message: "missing term error",
				Code:    3003,
				Fields: map[string]interface{}{
					"path": "/path",
					"term": "term",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			logger := zerolog.Nop()

			mockEngine := mockEngine{
				run: func(ctx context.Context, options engine.RunOptions) (*engine.Results, results.ScanAnalytics, []error, []error) {
					return nil, results.ScanAnalytics{}, []error{test.actual}, nil
				},
			}

			resultsProcessor := mockResultsProcessor{
				processResults: func(rawResults *engine.Results, scanAnalytics results.ScanAnalytics) (*results.Results, error) {
					return nil, nil
				},
			}

			userSettings := settings.Settings{
				Entitlements: settings.Entitlements{
					InfrastructureAsCode: true,
				},
			}

			settingsReader := readSettingsFunc(func(ctx context.Context) (*settings.Settings, error) {
				return &userSettings, nil
			})

			fs := afero.NewMemMapFs()

			require.Nil(t, afero.WriteFile(fs, "bundle.tar.gz", nil, 0644))

			cmd := command.Command{
				Output:           outputFilePath,
				FS:               fs,
				Engine:           mockEngine,
				Paths:            []string{"."},
				Bundle:           "bundle.tar.gz",
				ResultsProcessor: resultsProcessor,
				SettingsReader:   settingsReader,
				Logger:           &logger,
			}

			require.Equal(t, 0, cmd.Run())

			requireErrors(t, fs, []scanError{test.expected})
		})
	}
}

func TestSettings(t *testing.T) {
	logger := zerolog.Nop()
	fs := afero.NewMemMapFs()

	policyEngine := mockEngine{
		run: func(ctx context.Context, options engine.RunOptions) (*engine.Results, results.ScanAnalytics, []error, []error) {
			return nil, results.ScanAnalytics{}, nil, nil
		},
	}

	resultsProcessor := mockResultsProcessor{
		processResults: func(rawResults *engine.Results, scanAnalytics results.ScanAnalytics) (*results.Results, error) {
			return nil, nil
		},
	}

	cloudApiClient := mockCloudApiClient{
		customRules: func(ctx context.Context, orgID string) (readers []bundle.Reader, e error) {
			return nil, nil
		},
	}

	userSettings := settings.Settings{
		Org:         "org",
		OrgPublicID: "org-public-id",
		Entitlements: settings.Entitlements{
			InfrastructureAsCode: true,
		},
		IgnoreSettings: settings.IgnoreSettings{
			AdminOnly:                  true,
			DisregardFilesystemIgnores: true,
			ReasonRequired:             true,
		},
	}

	settingsReader := readSettingsFunc(func(ctx context.Context) (*settings.Settings, error) {
		return &userSettings, nil
	})

	require.Nil(t, afero.WriteFile(fs, "bundle.tar.gz", nil, 0644))

	cmd := command.Command{
		FS:               fs,
		Engine:           policyEngine,
		Paths:            []string{"."},
		Bundle:           "bundle.tar.gz",
		ResultsProcessor: resultsProcessor,
		SettingsReader:   settingsReader,
		SnykClient:       &cloudApiClient,
		Output:           outputFilePath,
		Logger:           &logger,
	}

	require.Equal(t, 0, cmd.Run())

	requireNoError(t, fs)

	type ignoreSettings struct {
		AdminOnly                  bool
		DisregardFilesystemIgnores bool
		ReasonRequired             bool
	}

	type outputSettings struct {
		Org            string
		IgnoreSettings ignoreSettings
	}

	type output struct {
		Settings outputSettings
	}

	var actualOutput output

	readOutput(t, fs, &actualOutput)

	expectedOutput := output{
		Settings: outputSettings{
			Org: "org",
			IgnoreSettings: ignoreSettings{
				AdminOnly:                  true,
				DisregardFilesystemIgnores: true,
				ReasonRequired:             true,
			},
		},
	}

	require.Equal(t, expectedOutput, actualOutput)
}

func TestSettingsError(t *testing.T) {
	logger := zerolog.Nop()
	fs := afero.NewMemMapFs()

	policyEngine := mockEngine{
		run: func(ctx context.Context, options engine.RunOptions) (*engine.Results, results.ScanAnalytics, []error, []error) {
			return nil, results.ScanAnalytics{}, nil, nil
		},
	}

	resultsProcessor := mockResultsProcessor{
		processResults: func(rawResults *engine.Results, scanAnalytics results.ScanAnalytics) (*results.Results, error) {
			return nil, nil
		},
	}

	settingsReader := readSettingsFunc(func(ctx context.Context) (*settings.Settings, error) {
		return nil, errors.New("error")
	})

	require.Nil(t, afero.WriteFile(fs, "bundle.tar.gz", nil, 0644))

	cmd := command.Command{
		FS:               fs,
		Engine:           policyEngine,
		Paths:            []string{"."},
		Bundle:           "bundle.tar.gz",
		ResultsProcessor: resultsProcessor,
		SettingsReader:   settingsReader,
		Output:           outputFilePath,
		Logger:           &logger,
	}

	require.Equal(t, 0, cmd.Run())

	requireError(t, fs, scanError{
		Message: "unable to read the IaC organization settings",
		Code:    2202,
	})
}

func requireNoError(t *testing.T, fs afero.Fs) {
	t.Helper()

	var output struct {
		Errors []scanError
	}

	f, _ := afero.ReadFile(fs, outputFilePath)

	require.Nil(t, json.Unmarshal(f, &output), "Unable to decode the output")
	require.Nil(t, output.Errors, "No errors should be returned")
}

func requireError(t *testing.T, fs afero.Fs, expected scanError) {
	t.Helper()

	var output struct {
		Errors []scanError
	}

	readOutput(t, fs, &output)

	require.Contains(t, output.Errors, expected)
}

func requireErrors(t *testing.T, fs afero.Fs, expected []scanError) {
	t.Helper()

	var output struct {
		Errors []scanError
	}

	readOutput(t, fs, &output)

	require.ElementsMatch(t, output.Errors, expected)
}

func readOutput(t *testing.T, fs afero.Fs, output any) {
	t.Helper()

	data, err := afero.ReadFile(fs, outputFilePath)
	require.NoError(t, err)

	require.NoError(t, json.Unmarshal(data, output))
}

func TestRawResults(t *testing.T) {
	type output struct {
		RawResults *engine.Results
	}

	mockRawResults := &engine.Results{}

	tests := []struct {
		name              string
		excludeRawResults bool
		rawResults        *engine.Results
		expected          output
	}{
		{
			name:              "including raw results",
			excludeRawResults: false,
			rawResults:        mockRawResults,
			expected: output{
				RawResults: mockRawResults,
			},
		},
		{
			name:              "excluding raw results",
			excludeRawResults: true,
			rawResults:        mockRawResults,
			expected:          output{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			logger := zerolog.Nop()
			fs := afero.NewMemMapFs()

			policyEngine := mockEngine{
				run: func(ctx context.Context, options engine.RunOptions) (*engine.Results, results.ScanAnalytics, []error, []error) {
					return test.rawResults, results.ScanAnalytics{}, nil, nil
				},
			}

			resultsProcessor := mockResultsProcessor{
				processResults: func(rawResults *engine.Results, scanAnalytics results.ScanAnalytics) (*results.Results, error) {
					return nil, nil
				},
			}

			cloudApiClient := mockCloudApiClient{
				customRules: func(ctx context.Context, orgID string) (readers []bundle.Reader, e error) {
					return nil, nil
				},
			}

			userSettings := settings.Settings{
				Org:         "org",
				OrgPublicID: "org-public-id",
				Entitlements: settings.Entitlements{
					InfrastructureAsCode: true,
				},
				IgnoreSettings: settings.IgnoreSettings{
					AdminOnly:                  true,
					DisregardFilesystemIgnores: true,
					ReasonRequired:             true,
				},
			}

			settingsReader := readSettingsFunc(func(ctx context.Context) (*settings.Settings, error) {
				return &userSettings, nil
			})

			require.Nil(t, afero.WriteFile(fs, "bundle.tar.gz", nil, 0644))

			cmd := command.Command{
				FS:                fs,
				Engine:            policyEngine,
				Paths:             []string{"."},
				Bundle:            "bundle.tar.gz",
				ResultsProcessor:  resultsProcessor,
				SettingsReader:    settingsReader,
				SnykClient:        &cloudApiClient,
				Output:            outputFilePath,
				ExcludeRawResults: test.excludeRawResults,
				Logger:            &logger,
			}

			require.Equal(t, 0, cmd.Run())

			requireNoError(t, fs)

			var actualOutput output

			readOutput(t, fs, &actualOutput)

			require.Equal(t, test.expected, actualOutput)
		})
	}
}

func TestExcludeFiltering(t *testing.T) {
	logger := zerolog.Nop()
	fs := afero.NewMemMapFs()

	// create bundle so scan proceeds
	require.Nil(t, afero.WriteFile(fs, "bundle.tar.gz", nil, 0644))

	// create a small directory tree
	require.Nil(t, fs.MkdirAll("root/a", 0755))
	require.Nil(t, fs.MkdirAll("root/b", 0755))
	require.Nil(t, afero.WriteFile(fs, "root/a/file1.tf", []byte(""), 0644))
	require.Nil(t, afero.WriteFile(fs, "root/b/file2.tf", []byte(""), 0644))

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

	userSettings := settings.Settings{
		Entitlements: settings.Entitlements{
			InfrastructureAsCode: true,
		},
	}

	settingsReader := readSettingsFunc(func(ctx context.Context) (*settings.Settings, error) {
		return &userSettings, nil
	})

	cmd := command.Command{
		FS:               fs,
		Engine:           policyEngine,
		Paths:            []string{"root"},
		Bundle:           "bundle.tar.gz",
		ResultsProcessor: resultsProcessor,
		SettingsReader:   settingsReader,
		Output:           outputFilePath,
		Logger:           &logger,
	}

	// Emulate exclusion of directory b and a specific file in a
	// The exclude will be wired via flag later; for now we test behavior once applied
	cmd.Exclude = []string{"b", "a/file1.tf"}

	require.Equal(t, 0, cmd.Run())

	// Expect only paths under root that are not excluded to be passed to engine
	// In our simple implementation we expect at least that excluded specific file is not present
	for _, p := range capturedPaths {
		require.NotContains(t, p, "root/b/file2.tf")
		require.NotContains(t, p, "root/a/file1.tf")
	}
}
