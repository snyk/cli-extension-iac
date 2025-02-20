package iactest

import (
	"fmt"
	"github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"os"
	"path/filepath"
	"strings"
)

var (
	unsupportedFlagsIaCPlus = []string{FlagProjectTags, FlagProjectEnvironment, FlagProjectLifecycle, FlagProjectBusinessCriticality}
	unsupportedFlagsIaCV2   = []string{FlagSnykCloudEnvironment}

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
	err := checkUnsupportedFlags(config, unsupportedFlagsIaCV2)
	if err != nil {
		return err
	}

	err = validateReportConfig(config)
	if err != nil {
		return err
	}

	return nil
}

func validateIacPlusConfig(config configuration.Configuration) error {
	return checkUnsupportedFlags(config, unsupportedFlagsIaCPlus)
}

func validateCommonConfig(config configuration.Configuration) error {
	if config.IsSet(FlagVarFile) {
		err := validateVarFile(config)
		if err != nil {
			return err
		}
	}

	if config.IsSet(FlagSeverityThreshold) {
		flag := flagWithValues{
			name:        FlagSeverityThreshold,
			allowEmpty:  false,
			validValues: validOptionsCriticality,
		}
		err := validateFlagValue(config, flag)
		if err != nil {
			return err
		}
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

type flagWithValues struct {
	name        string
	allowEmpty  bool
	validValues map[string]struct{}
}

/*
	This validates config flags that only work together with --report:

--project-environment, --project-business-criticality, --project-lifecycle
--project-tags or --tags
*/
func validateReportConfig(config configuration.Configuration) error {
	flags := []flagWithValues{
		{
			name:        FlagProjectEnvironment,
			allowEmpty:  true,
			validValues: validOptionsProjectEnv,
		},
		{
			name:        FlagProjectLifecycle,
			allowEmpty:  true,
			validValues: validOptionsProjectLifecycle,
		},
		{
			name:        FlagProjectBusinessCriticality,
			allowEmpty:  true,
			validValues: validOptionsCriticality,
		},
	}

	for _, flag := range flags {
		// if flag is not set in config, no need to check it
		if !config.IsSet(flag.name) {
			continue
		}

		// if flag is set without setting --report throw error
		if !config.GetBool(FlagReport) {
			return invalidReportOptionError(flag.name)
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
func validateFlagValue(config configuration.Configuration, flag flagWithValues) error {
	rawFlagValue := config.GetString(flag.name)
	if rawFlagValue == "" && flag.allowEmpty {
		return nil
	}

	rawValues := strings.Split(rawFlagValue, ",")

	var invalidValues []string
	for _, v := range rawValues {
		if _, exists := flag.validValues[v]; !exists {
			invalidValues = append(invalidValues, v)
		}
	}

	if len(invalidValues) > 0 {
		errMsg := fmt.Sprintf("%d invalid %s: %v. Possible values are: %v", len(invalidValues), flag.name, strings.Join(invalidValues, ", "), strings.Join(getKeys(flag.validValues), ", "))
		if flag.allowEmpty {
			errMsg += fmt.Sprintf("\nTo clear all existing values, pass no values i.e. %s=", flag.name)
		}
		return cli.NewInvalidFlagOptionError(errMsg)
	}

	return nil
}

/*
	This validates the --tags and --project-tags config flags

allowed usage: only together with --report and can't be both set at the same time\n
format: KEY=VALUE
*/
func validateTags(config configuration.Configuration) error {
	// no flag is set no need to validate
	if !config.IsSet(FlagTags) && !config.IsSet(FlagProjectTags) {
		return nil
	}

	// can't have both --tags and --project-tags at the same time
	if config.IsSet(FlagTags) && config.IsSet(FlagProjectTags) {
		errMsg := "Only one of --tags or --project-tags may be specified, not both"
		return cli.NewInvalidFlagOptionError(errMsg)
	}

	// tags only work with --report
	if !config.GetBool(FlagReport) {
		return invalidReportOptionError(FlagProjectTags)
	}

	rawTags := ""
	if config.IsSet(FlagTags) {
		rawTags = config.GetString(FlagTags)
	}

	if config.IsSet(FlagProjectTags) {
		rawTags = config.GetString(FlagProjectTags)
	}

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

func invalidReportOptionError(option string) error {
	errMsg := fmt.Sprintf("--%s can only be used together with --%s ", option, FlagReport)
	errMsg += fmt.Sprintf("and must contain a '=' with a comma-separated list of values.")
	errMsg += fmt.Sprintf("To clear all existing values, pass no values i.e. --%s=", option)
	return cli.NewInvalidFlagOptionError(errMsg)
}

func getKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	return keys
}
