package iactest

import (
	"github.com/spf13/pflag"
)

const (
	FlagReport                     = "report"
	FlagSeverityThreshold          = "severity-threshold"
	FlagIgnorePolicy               = "ignore-policy"
	FlagPolicyPath                 = "policy-path"
	FlagTargetReference            = "target-reference"
	FlagTargetName                 = "target-name"
	FlagRemoteRepoURL              = "remote-repo-url"
	FlagSnykCloudEnvironment       = "snyk-cloud-environment"
	FlagScan                       = "scan"
	FlagDepthDetection             = "detection-depth"
	FlagVarFile                    = "var-file"
	FlagJson                       = "json"
	FlagJsonFileOutput             = "json-file-output"
	FlagSarif                      = "sarif"
	FlagSarifFileOutput            = "sarif-file-output"
	FlagProjectBusinessCriticality = "project-business-criticality"
	FlagProjectEnvironment         = "project-environment"
	FlagProjectLifecycle           = "project-lifecycle"
	FlagProjectTags                = "project-tags"
	FlagRules                      = "rules"
)

func GetIaCTestFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("snyk-cli-extension-iac-test", pflag.ExitOnError)

	/*
		The flags declared here are a combination of the flags used in  current IaC/IaC+/IaCv2, as this extension is the entry point for all IaC workflows.
		Failing to declare a flag here will result in the flag not being recognized by the CLI.

		Flags like --org are not declared here because they are declared in the root command.
		Adding them here may result in unexpected behavior.
	*/
	flagSet.Int(FlagDepthDetection, 0, "Indicate how many levels of subdirectories to search. Must be a number, 1 or greater; zero (0) is the current directory.")
	flagSet.String(FlagSnykCloudEnvironment, "", "ID of the Snyk Cloud environment to get context for scan.")
	//nolint:lll // Long flag description
	flagSet.String(FlagScan, "resource-changes", "Use this dedicated option for Terraform plan scanning modes to control whether the scan analyzes the full final state or the proposed changes only.")
	flagSet.String(FlagVarFile, "", "Use this option to load a terraform variable definitions file that is located in a different directory from the scanned one.")
	flagSet.Bool(FlagIgnorePolicy, false, "Ignore the policy file.")
	flagSet.String(FlagPolicyPath, "", "Path to a .snyk policy file.")
	flagSet.String(FlagSeverityThreshold, "", "Report only vulnerabilities at the specified level or higher.")
	flagSet.Bool(FlagReport, false, "Share results with the Snyk Web UI.")
	flagSet.String(FlagTargetName, "", "Used in Share Results to set or override the project name for the repository. ")
	flagSet.String(FlagTargetReference, "", "Used in Share Results to specify a reference which differentiates this project, e.g. a branch name or version.")
	flagSet.String(FlagRemoteRepoURL, "", "Used in Share Results to set or override the remote URL for the repository. ")
	flagSet.Bool(FlagJson, false, "Print results on the console as a JSON data structure.")
	flagSet.String(FlagJsonFileOutput, "", "Save test output as a JSON data structure directly to the specified file, regardless of whether or not you use the --json option.")
	flagSet.Bool(FlagSarif, false, "Return results in SARIF format.")
	flagSet.String(FlagSarifFileOutput, "", "Save test output in SARIF format directly to the specified file, regardless of whether or not you use the --sarif option.")
	flagSet.String(FlagProjectBusinessCriticality, "", "Set the project business criticality project attribute to one or more values (comma-separated).")
	flagSet.String(FlagProjectEnvironment, "", "Set the project environment project attribute to one or more values (comma-separated).")
	flagSet.String(FlagProjectLifecycle, "", "Set the project lifecycle project attribute to one or more values (comma-separated).")
	flagSet.String(FlagProjectTags, "", "Set the project tags to one or more values (comma-separated key value pairs with an \"=\" separator).")
	flagSet.String(FlagRules, "", "Path to a directory containing custom rules.")

	return flagSet
}
