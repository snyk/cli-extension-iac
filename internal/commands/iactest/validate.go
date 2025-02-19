package iactest

import (
	"fmt"
	"github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"strings"
)

var (
	unsupportedFlagsIaCPlus      = []string{FlagProjectTags, FlagProjectEnvironment, FlagProjectLifecycle, FlagProjectBusinessCriticality}
	unsupportedFlagsIaCV2        = []string{FlagSnykCloudEnvironment}
	validOptionsCriticality      = []string{"critical", "high", "medium", "low"}
	validOptionsProjectEnv       = []string{"frontend", "backend", "internal", "external", "mobile", "saas", "onprem", "hosted", "distributed"}
	validOptionsProjectLifecycle = []string{"production", "development", "sandbox"}
)

type flagWithOpts struct {
	name         string
	allowEmpty   bool
	validOptions []string
}

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
	// TODO validate var-file

	if config.IsSet(FlagSeverityThreshold) {
		flag := flagWithOpts{
			name:         FlagSeverityThreshold,
			allowEmpty:   false,
			validOptions: validOptionsCriticality,
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

func validateFlagValue(config configuration.Configuration, flag flagWithOpts) error {
	rawProjectEnvironment := config.GetString(flag.name)
	if rawProjectEnvironment == "" && flag.allowEmpty {
		return nil
	}

	projectEnvs := strings.Split(rawProjectEnvironment, ",")

	valid := make(map[string]bool)
	for _, projectEnv := range projectEnvs {
		valid[projectEnv] = false
		for _, validEnv := range flag.validOptions {
			if projectEnv == validEnv {
				valid[projectEnv] = true
				break
			}
		}
	}

	invalidAttributes := []string{}
	for k, v := range valid {
		if v == false {
			invalidAttributes = append(invalidAttributes, k)
		}
	}

	if len(invalidAttributes) > 0 {
		errMsg := fmt.Sprintf("%d invalid project-environment: %v. Possible values are: %v", len(invalidAttributes), strings.Join(invalidAttributes, ", "), strings.Join(validValues, ", "))
		if flag.allowEmpty {
			errMsg += fmt.Sprintf("\nTo clear all existing values, pass no values i.e. %s=", flag)
		}
		return cli.NewInvalidFlagOptionError(errMsg)
	}

	return nil
}

func validateReportConfig(config configuration.Configuration) error {
	flags := []flagWithOpts{
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
		// if flag is not set in config, no need to check it
		if !config.IsSet(flag.name) {
			continue
		}

		// if flag is set without setting --report throw error
		if !config.GetBool(FlagReport) {
			return invalidReportOptionError(flag.name)
		}

		// validate the flag's value(s)
		err := validateFlagValue(config, flag.name, flag.validOptions, flag.allowEmpty)
		if err != nil {
			return err
		}
	}

	err := validateTags(config)
	if err != nil {
		return err
	}

	return nil
}

func validateTags(config configuration.Configuration) error {
	if !config.IsSet(FlagTags) && !config.IsSet(FlagProjectTags) {
		return nil
	}

	if config.IsSet(FlagTags) && config.IsSet(FlagProjectTags) {
		errMsg := "Only one of --tags or --project-tags may be specified, not both"
		return cli.NewInvalidFlagOptionError(errMsg)
	}

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

func invalidReportOptionError(option string) error {
	errMsg := fmt.Sprintf("--%s can only be used together with --%s ", option, FlagReport)
	errMsg += fmt.Sprintf("and must contain a '=' with a comma-separated list of values.")
	errMsg += fmt.Sprintf("To clear all existing values, pass no values i.e. --%s=", option)
	return cli.NewInvalidFlagOptionError(errMsg)
}
