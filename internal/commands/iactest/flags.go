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
	FlagDepthDetection             = "depth-detection"
	FlagVarFile                    = "var-file"
	FlagJson                       = "json"
	FlagSarif                      = "sarif"
	FlagProjectEnvironment         = "project-environment"
	FlagProjectBusinessCriticality = "project-business-criticality"
	FlagProjectLifecycle           = "project-lifecycle"
	FlagProjectTags                = "project-tags"
	FlagTags                       = "tags"
)

func GetIaCTestFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("snyk-cli-extension-iac-test", pflag.ExitOnError)

	flagSet.Int(FlagDepthDetection, 0, "Indicate how many levels of subdirectories to search. Must be a number, 1 or greater; zero (0) is the current directory.")
	flagSet.String(FlagSnykCloudEnvironment, "", "ID of the Snyk Cloud environment to get context for scan ")
	//nolint:lll // Long flag description
	flagSet.String(FlagScan, "resource-changes", "Use this dedicated option for Terraform plan scanning modes to control whether the scan analyzes the full final state or the proposed changes only")
	flagSet.String(FlagVarFile, "", "Use this option to load a terraform variable definitions file that is located in a different directory from the scanned one")
	flagSet.Bool(FlagIgnorePolicy, false, "Ignore the policy file")
	flagSet.String(FlagPolicyPath, "", "Path to a .snyk policy file")
	flagSet.String(FlagSeverityThreshold, "", "Report only vulnerabilities at the specified level or higher")
	flagSet.Bool(FlagReport, false, "Share results with the Snyk Web UI")
	flagSet.String(FlagTargetName, "", "Used in Share Results to set or override the project name for the repository. ")
	flagSet.String(FlagTargetReference, "", "Used in Share Results to specify a reference which differentiates this project, e.g. a branch name or version")
	flagSet.String(FlagRemoteRepoURL, "", "Used in Share Results to set or override the remote URL for the repository. ")
	flagSet.Bool(FlagJson, false, "Print results on the console as a JSON data structure")
	flagSet.Bool(FlagSarif, false, "Return results in SARIF format.")
	flagSet.String(FlagProjectEnvironment, "", "Set the project environment project attribute to one or more values")
	flagSet.String(FlagProjectLifecycle, "", " Set the project lifecycle project attribute to one or more values")
	flagSet.String(FlagProjectBusinessCriticality, "", "Set the project business criticality project attribute to one or more values")
	flagSet.String(FlagProjectTags, "", " Set the project tags to one or more values")
	flagSet.String(FlagTags, "", " Set the project tags to one or more values")

	return flagSet
}
