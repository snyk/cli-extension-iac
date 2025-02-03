package main

import (
	"log"
	"os"

	"github.com/spf13/pflag"

	"github.com/snyk/cli-extension-iac/pkg/iac"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/devtools"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func initMockLegacy(e workflow.Engine) error {
	flagset := pflag.NewFlagSet("legacycli", pflag.ContinueOnError)
	flagset.StringSlice(configuration.RAW_CMD_ARGS, os.Args[1:], "Command line arguments for the legacy CLI.")
	flagset.Bool(configuration.WORKFLOW_USE_STDIO, false, "Use StdIn and StdOut")
	flagset.String(configuration.WORKING_DIRECTORY, "", "CLI working directory")

	config := workflow.ConfigurationOptionsFromFlagset(flagset)
	_, err := e.Register(workflow.NewWorkflowIdentifier("legacycli"), config, legacycliWorkflow)
	return err
}

func legacycliWorkflow(
	invocation workflow.InvocationContext,
	_ []workflow.Data,
) (output []workflow.Data, err error) {
	output = []workflow.Data{}
	config := invocation.GetConfiguration()
	args := config.GetStringSlice(configuration.RAW_CMD_ARGS)
	useStdIo := config.GetBool(configuration.WORKFLOW_USE_STDIO)
	workingDirectory := config.GetString(configuration.WORKING_DIRECTORY)
	debugLogger := invocation.GetLogger()

	debugLogger.Print("Arguments:", args)
	debugLogger.Print("Use StdIO:", useStdIo)
	debugLogger.Print("Working directory:", workingDirectory)

	return output, nil
}

func main() {
	cmd, err := devtools.Cmd(iac.Init, initMockLegacy)
	if err != nil {
		log.Fatal(err)
	}
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
