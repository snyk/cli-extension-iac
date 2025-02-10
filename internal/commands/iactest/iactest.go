package iactest

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/spf13/afero"

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
	RulesClientURL   = "snyk_iac_rules_client_url"
	RulesBundlePath  = "snyk_iac_bundle_path"
	DisableAnalytics = "snyk_disable_analytics"

	DotSnykPolicy = ".snyk"
)

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
	logger := ictx.GetLogger()
	args := os.Args[1:]

	if config.GetBool(FeatureFlagNewEngine) || config.GetBool(FeatureFlagIntegratedExperience) {
		logger.Print("IaC new engine enabled")
		outputFile, err := runNewEngine(ictx)
		if err != nil {
			// TODO: check that the possible errors are properly formatted
			return nil, err
		}
		args = append(args, fmt.Sprintf("--%s=%s", LegacyFlagOutputFile, outputFile))
	}

	// The legacy workflow is invoked for both the new and legacy IaC engines
	config.Set(configuration.RAW_CMD_ARGS, args)
	config.Set(configuration.WORKFLOW_USE_STDIO, true)
	return workflowEngine.InvokeWithConfig(workflow.NewWorkflowIdentifier("legacycli"), config)
}

func runNewEngine(ictx workflow.InvocationContext) (string, error) {
	config := ictx.GetConfiguration()
	debugLogger := ictx.GetEnhancedLogger()

	ui := NewUI(UIConfig{
		Logger:   debugLogger,
		Backend:  ictx.GetUserInterface(),
		Disabled: config.GetBool(FlagJson) || config.GetBool(FlagSarif),
	})
	ui.Output(fmt.Sprintf("\n%s\n", renderBold("Snyk Infrastructure As Code")))
	ui.StartProgressBar("Snyk testing Infrastructure as Code configuration issues.")
	defer func() {
		ui.ClearProgressBar()
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
		StubResources:          results.StubResources,
		SerializeEngineResults: cloudapi.SerializeEngineResults,
	}

	policyPath := ""
	if !config.GetBool(FlagIgnorePolicy) {
		cwd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("error getting current working directory: %v", err)
		}
		policyPath = GetPolicyFile(config.GetString(FlagPolicyPath), cwd, debugLogger)
	}

	resultsProcessor := processor.ResultsProcessor{
		SnykPlatform:                 &snykPlatform,
		Report:                       config.GetBool(FlagReport),
		SeverityThreshold:            config.GetString(FlagSeverityThreshold),
		TargetReference:              config.GetString(FlagTargetReference),
		TargetName:                   config.GetString(FlagTargetName),
		RemoteRepoUrl:                config.GetString(FlagRemoteRepoURL),
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

	paths := []string{config.GetString(configuration.INPUT_DIRECTORY)}

	cmd := command.Command{
		Output:                  outputFile,
		Logger:                  debugLogger,
		Engine:                  &policyEngine,
		FS:                      fs,
		Paths:                   paths,
		Bundle:                  config.GetString(RulesBundlePath),
		ResultsProcessor:        &resultsProcessor,
		SnykCloudEnvironment:    config.GetString(FlagSynkCloudEnvironment),
		SnykClient:              cloudapiClient,
		Scan:                    config.GetString(FlagScan),
		DetectionDepth:          config.GetInt(FlagDepthDetection),
		VarFile:                 config.GetString(FlagVarFile),
		SettingsReader:          &cachedSettingsReader,
		BundleDownloader:        &rulesClient,
		ReadPolicyEngineVersion: command.ReadRuntimePolicyEngineVersion,
		ExcludeRawResults:       true,
		AllowAnalytics:          !config.GetBool(DisableAnalytics),
		Report:                  config.GetBool(FlagReport),
		IacNewEngine:            config.GetBool(FeatureFlagNewEngine),
	}

	if err := cmd.RunWithError(); err != nil {
		// TODO: proper error message
		return "", fmt.Errorf("error running snyk-iac-test: %v", err)
	}

	return outputFile, nil
}
