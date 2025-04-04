package iactest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

var (
	projectAttributesFlags = []string{FlagProjectTags, FlagProjectEnvironment, FlagProjectLifecycle, FlagProjectBusinessCriticality}
	unsupportedFlagsIaCV2  = []string{FlagSnykCloudEnvironment}

	validOptionsCriticality = map[string]struct{}{
		"critical": {}, "high": {}, "medium": {}, "low": {}}
	validOptionsProjectEnv = map[string]struct{}{
		"frontend": {}, "backend": {}, "internal": {}, "external": {}, "mobile": {}, "saas": {}, "onprem": {}, "hosted": {}, "distributed": {}}
	validOptionsProjectLifecycle = map[string]struct{}{
		"production": {}, "development": {}, "sandbox": {}}
)

const tfVarExt = ".tfvars"

func validateConfig(config configuration.Configuration) error {
	if config.GetBool(FeatureFlagNewEngine) {
		err := validateIacV2Config(config)
		if err != nil {
			return err
		}
	}

	if config.GetBool(FeatureFlagIntegratedExperience) {
		err := validateIacPlusConfig(config)
		if err != nil {
			return err
		}
	}

	return validateCommonConfig(config)
}

func validateIacV2Config(config configuration.Configuration) error {
	// check unsupported flags for IaC V2
	err := checkUnsupportedFlags(config, unsupportedFlagsIaCV2)
	if err != nil {
		return err
	}

	// check --report related flags only if --report is true, otherwise flags are ignored
	if config.GetBool(FlagReport) {
		err = validateReportConfig(config)
		if err != nil {
			return err
		}
	}

	return nil
}

func validateIacPlusConfig(config configuration.Configuration) error {
	// check unsupported flags for IaC+
	return checkUnsupportedFlags(config, projectAttributesFlags)
}

func validateCommonConfig(config configuration.Configuration) error {
	if config.IsSet(FlagVarFile) {
		err := validateVarFile(config)
		if err != nil {
			return err
		}
	}

	if config.IsSet(FlagSeverityThreshold) {
		flag := flagWithOptions{
			name:         FlagSeverityThreshold,
			allowEmpty:   false,
			singleChoice: true,
			validOptions: validOptionsCriticality,
		}
		err := validateFlagValue(config, flag)
		if err != nil {
			return err
		}
	}

	if config.GetString(RulesClientURL) == "" {
		return cli.NewGeneralIACFailureError("A rule bundle must be provided using the IAC_RULES_URL env var in the CLI build command. Example: IAC_RULES_URL=<url> make build")
	}

	return nil
}

func checkUnsupportedFlags(config configuration.Configuration, unsupportedFlags []string) error {
	for _, f := range unsupportedFlags {
		if config.IsSet(f) {
			return cli.NewInvalidFlagOptionError(fmt.Sprintf("Unsupported flag %s provided. Run snyk iac test --help for supported flags", f))
		}
	}
	return nil
}

type flagWithOptions struct {
	name         string
	allowEmpty   bool
	singleChoice bool
	validOptions map[string]struct{}
}

/*
	This validates config flags that only work together with --report:

--project-environment, --project-business-criticality, --project-lifecycle
--project-tags
*/
func validateReportConfig(config configuration.Configuration) error {
	flags := []flagWithOptions{
		{
			name:         FlagProjectEnvironment,
			allowEmpty:   true,
			validOptions: validOptionsProjectEnv,
		},
		{
			name:         FlagProjectLifecycle,
			allowEmpty:   true,
			validOptions: validOptionsProjectLifecycle,
		},
		{
			name:         FlagProjectBusinessCriticality,
			allowEmpty:   true,
			validOptions: validOptionsCriticality,
		},
	}

	for _, flag := range flags {
		// if flag is not set, no need to check it
		if !config.IsSet(flag.name) {
			continue
		}

		// validate the flag's value(s)
		err := validateFlagValue(config, flag)
		if err != nil {
			return err
		}
	}

	// tags need to adhere to a specific KEY=VALUE format
	err := validateTags(config)
	if err != nil {
		return err
	}

	return nil
}

/*
	Validates a config flag that can only take one of a specific set of values

e.g. --severity-threshold must be one of low, medium, high, critical
*/
func validateFlagValue(config configuration.Configuration, flag flagWithOptions) error {
	rawFlagValue := config.GetString(flag.name)
	if rawFlagValue == "" && flag.allowEmpty {
		return nil
	}

	rawValues := strings.Split(rawFlagValue, ",")

	if len(rawValues) > 1 && flag.singleChoice {
		errMsg := fmt.Sprintf("Invalid --%s, please use one of %s ", flag.name, strings.Join(getKeys(flag.validOptions), " | "))
		return cli.NewInvalidFlagOptionError(errMsg)
	}

	var invalidValues []string
	for _, v := range rawValues {
		if _, exists := flag.validOptions[v]; !exists {
			invalidValues = append(invalidValues, v)
		}
	}

	if len(invalidValues) > 0 {
		errMsg := fmt.Sprintf("%d invalid %s: %v. Possible values are: %v", len(invalidValues), flag.name, strings.Join(invalidValues, ", "), strings.Join(getKeys(flag.validOptions), ", "))
		if flag.allowEmpty {
			errMsg += fmt.Sprintf("\nTo clear all existing values, pass no values i.e. %s=", flag.name)
		}
		return cli.NewInvalidFlagOptionError(errMsg)
	}

	return nil
}

/*
	This validates the --project-tags config flag

format: KEY=VALUE
*/
func validateTags(config configuration.Configuration) error {
	// no flag is set no need to validate
	if !config.IsSet(FlagProjectTags) {
		return nil
	}

	rawTags := config.GetString(FlagProjectTags)
	if rawTags == "" {
		return nil
	}

	// tags must have a specific KEY=VALUE format
	tags := strings.Split(rawTags, ",")
	for _, t := range tags {
		tagParts := strings.Split(t, "=")
		if len(tagParts) != 2 {
			errMsg := fmt.Sprintf("The tag %s does not have an \"=\" separating the key and value. For example: %s=KEY=VALUE", t, FlagProjectTags)
			errMsg += fmt.Sprintf("\nTo clear all existing values, pass no values i.e. %s=", FlagProjectTags)
			return cli.NewInvalidFlagOptionError(errMsg)
		}
	}

	return nil
}

func validateVarFile(config configuration.Configuration) error {
	varFile := config.GetString(FlagVarFile)
	_, err := os.Stat(varFile)

	if os.IsNotExist(err) {
		return cli.NewInvalidFlagOptionError(fmt.Sprintf("We were unable to locate a variable definitions file at: %s. The file at the provided path does not exist", varFile))
	}

	ext := filepath.Ext(varFile)
	if ext != tfVarExt {
		errMsg := fmt.Sprintf("Unsupported value %s provided to --%s. Supported values are: %s", varFile, FlagVarFile, tfVarExt)
		return cli.NewInvalidFlagOptionError(errMsg)
	}

	return nil
}

func getKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	return keys
}
