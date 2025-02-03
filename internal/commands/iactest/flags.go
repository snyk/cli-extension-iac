package iactest

import "github.com/spf13/pflag"

const (
	FlagReport               = "report"
	FlagSeverityThreshold    = "severity-threshold"
	FlagIgnorePolicy         = "ignore-policy"
	FlagPolicyPath           = "policy-path"
	FlagTargetReference      = "target-reference"
	FlagTargetName           = "target-name"
	FlagRemoteRepoURL        = "remote-repo-url"
	FlagSynkCloudEnvironment = "snyk-cloud-environment"
	FlagScan                 = "scan"
	FlagDepthDetection       = "depth-detection"
	FlagVarFile              = "var-file"
)

func GetIaCTestFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("snyk-cli-extension-iac-test", pflag.ExitOnError)

	flagSet.Int(FlagDepthDetection, 0, "Indicate how many levels of subdirectories to search. Must be a number, 1 or greater; zero (0) is the current directory.")
	flagSet.String(FlagSynkCloudEnvironment, "", "ID of the Snyk Cloud environment to get context for scan ")
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

	return flagSet
}
