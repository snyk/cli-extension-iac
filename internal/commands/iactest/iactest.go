package iactest

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/spf13/afero"

	"github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-iac/internal/cloudapi"
	"github.com/snyk/cli-extension-iac/internal/command"
	"github.com/snyk/cli-extension-iac/internal/engine"
	"github.com/snyk/cli-extension-iac/internal/git"
	"github.com/snyk/cli-extension-iac/internal/platform"
	"github.com/snyk/cli-extension-iac/internal/processor"
	"github.com/snyk/cli-extension-iac/internal/registry"
	"github.com/snyk/cli-extension-iac/internal/results"
	"github.com/snyk/cli-extension-iac/internal/rules"
	"github.com/snyk/cli-extension-iac/internal/settings"
)

const (
	LegacyFlagOutputFile = "iac-test-output-file"

	FeatureFlagNewEngine            = "iacNewEngine"
	FeatureFlagIntegratedExperience = "iacIntegratedExperience"

	// configuration keys.
	RulesClientURL  = "snyk_iac_rules_client_url"
	RulesBundlePath = "snyk_iac_bundle_path"

	DotSnykPolicy = ".snyk"
)

// injected in the CLI build process
var internalRulesClientURL string

var WorkflowID = workflow.NewWorkflowIdentifier("iac.test")

func RegisterWorkflows(e workflow.Engine) error {
	flagSet := GetIaCTestFlagSet()

	c := workflow.ConfigurationOptionsFromFlagset(flagSet)

	if _, err := e.Register(WorkflowID, c, TestWorkflow); err != nil {
		return fmt.Errorf("error while registering %s workflow: %w", WorkflowID, err)
	}

	config_utils.AddFeatureFlagToConfig(e, FeatureFlagNewEngine, FeatureFlagNewEngine)
	config_utils.AddFeatureFlagToConfig(e, FeatureFlagIntegratedExperience, FeatureFlagIntegratedExperience)
	return nil
}

func TestWorkflow(
	ictx workflow.InvocationContext,
	_ []workflow.Data,
) ([]workflow.Data, error) {
	config := ictx.GetConfiguration()
	workflowEngine := ictx.GetEngine()
	args := os.Args[1:]

	if config.GetBool(FeatureFlagNewEngine) || config.GetBool(FeatureFlagIntegratedExperience) {
		config.AddDefaultValue(RulesClientURL, configuration.StandardDefaultValueFunction(internalRulesClientURL))
		err := validateConfig(config)
		if err != nil {
			return nil, err
		}

		cwd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("error getting current working directory: %v", err)
		}
		inputPaths := DetermineInputPaths(args, cwd)
		outputFile, err := runNewEngine(ictx, inputPaths, cwd)
		if err != nil {
			return nil, err
		}
		args = append(args, fmt.Sprintf("--%s=%s", LegacyFlagOutputFile, outputFile))
	}

	// The legacy workflow is invoked for both the new and legacy IaC engines
	config.Set(configuration.RAW_CMD_ARGS, args)
	config.Set(configuration.WORKFLOW_USE_STDIO, true)
	return workflowEngine.InvokeWithConfig(workflow.NewWorkflowIdentifier("legacycli"), config)
}

func runNewEngine(ictx workflow.InvocationContext, inputPaths []string, cwd string) (string, error) {
	config := ictx.GetConfiguration()
	debugLogger := ictx.GetEnhancedLogger()

	ui := NewUI(UIConfig{
		Logger:   debugLogger,
		Backend:  ictx.GetUserInterface(),
		Disabled: config.GetBool(FlagJson) || config.GetBool(FlagSarif),
	})
	ui.DisplayTitle()
	ui.StartProgressBar()

	successful := true
	defer func() {
		ui.ClearProgressBar()
		if successful {
			ui.DisplayCompleted()
		}
	}()

	httpClient := ictx.GetNetworkAccess().GetHttpClient()

	fs := afero.NewOsFs()

	policyEngine := engine.Engine{
		FS: fs,
	}

	rulesClientURL := config.GetString(RulesClientURL)

	rulesClient := rules.Client{
		HTTPClient: httpClient,
		URL:        rulesClientURL,
	}

	var apiURL = config.GetString(configuration.API_URL)

	registryClient := registry.NewClient(registry.ClientConfig{
		HTTPClient: httpClient,
		URL:        apiURL,
	})

	settingsReader := settings.Reader{
		RegistryClient: registryClient,
		Org:            config.GetString(configuration.ORGANIZATION),
	}

	cachedSettingsReader := settings.CachedReader{
		Reader: &settingsReader,
	}

	cloudapiClient := cloudapi.NewClient(cloudapi.ClientConfig{
		HTTPClient:   httpClient,
		URL:          apiURL,
		Version:      "2022-04-13~experimental",
		IacNewEngine: config.GetBool(FeatureFlagNewEngine),
	})

	snykPlatform := platform.SnykPlatformClient{
		RestAPIURL:             apiURL,
		CloudAPIClient:         cloudapiClient,
		RegistryClient:         registryClient,
		StubResources:          results.StubResources,
		SerializeEngineResults: cloudapi.SerializeEngineResults,
	}

	policyPath := ""
	if !config.GetBool(FlagIgnorePolicy) {
		policyPath = GetPolicyFile(config.GetString(FlagPolicyPath), cwd, debugLogger)
	}

	projectAttributes := GetProjectAttributes(config)

	resultsProcessor := processor.ResultsProcessor{
		SnykPlatform:                 &snykPlatform,
		Report:                       config.GetBool(FlagReport),
		SeverityThreshold:            config.GetString(FlagSeverityThreshold),
		TargetReference:              config.GetString(FlagTargetReference),
		TargetName:                   config.GetString(FlagTargetName),
		RemoteRepoUrl:                config.GetString(FlagRemoteRepoURL),
		ProjectEnvironment:           projectAttributes.ProjectEnvironment,
		ProjectBusinessCriticality:   projectAttributes.ProjectBusinessCriticality,
		ProjectLifecycle:             projectAttributes.ProjectLifecycle,
		ProjectTags:                  projectAttributes.ProjectTags,
		GetWd:                        os.Getwd,
		GetRepoRootDir:               git.GetRepoRootDir,
		GetOriginUrl:                 git.GetOriginUrl,
		SettingsReader:               &cachedSettingsReader,
		PolicyPath:                   policyPath,
		IncludePassedVulnerabilities: true,
		IacNewEngine:                 config.GetBool(FeatureFlagNewEngine),
		Logger:                       debugLogger,
	}

	outputFile := filepath.Join(config.GetString(configuration.TEMP_DIR_PATH), fmt.Sprintf("snyk-iac-test-output-%s.json", uuid.NewString()))

	cmd := command.Command{
		Output:                  outputFile,
		Logger:                  debugLogger,
		Engine:                  &policyEngine,
		FS:                      fs,
		Paths:                   inputPaths,
		Bundle:                  config.GetString(RulesBundlePath),
		ResultsProcessor:        &resultsProcessor,
		SnykCloudEnvironment:    config.GetString(FlagSnykCloudEnvironment),
		SnykClient:              cloudapiClient,
		Scan:                    config.GetString(FlagScan),
		DetectionDepth:          config.GetInt(FlagDepthDetection),
		VarFile:                 config.GetString(FlagVarFile),
		SettingsReader:          &cachedSettingsReader,
		BundleDownloader:        &rulesClient,
		ReadPolicyEngineVersion: command.ReadRuntimePolicyEngineVersion,
		ExcludeRawResults:       true,
		AllowAnalytics:          !config.GetBool(configuration.ANALYTICS_DISABLED),
		Report:                  config.GetBool(FlagReport),
		IacNewEngine:            config.GetBool(FeatureFlagNewEngine),
	}

	successful, err := cmd.RunWithError()
	if err != nil {
		return "", cli.NewGeneralIACFailureError(err.Error(), snyk_errors.WithCause(err))
	}

	return outputFile, nil
}
