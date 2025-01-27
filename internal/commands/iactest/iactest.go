package iactest

import (
	"os"
	"fmt"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
)

var WorkflowID = workflow.NewWorkflowIdentifier("iac.test")

func RegisterWorkflows(e workflow.Engine) error {
	flagSet := GetIaCTestFlagSet()

	c := workflow.ConfigurationOptionsFromFlagset(flagSet)

	if _, err := e.Register(WorkflowID, c, TestWorkflow); err != nil {
		return fmt.Errorf("error while registering %s workflow: %w", WorkflowID, err)
	}
	return nil
}

func GetIaCTestFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("snyk-cli-extension-iac-test", pflag.ExitOnError)

	return flagSet
}

func TestWorkflow(
	ictx workflow.InvocationContext,
	_ []workflow.Data,
) ([]workflow.Data, error) {
	config := ictx.GetConfiguration()
	workflowEngine := ictx.GetEngine()
	logger := ictx.GetLogger()
	args := os.Args[1:]

	logger.Println("IaC Test workflow")

	// The legacy workflow is invoked for both the new and legacy IaC engines
	config.Set(configuration.RAW_CMD_ARGS, args)
	config.Set(configuration.WORKFLOW_USE_STDIO, true)
	return workflowEngine.InvokeWithConfig(workflow.NewWorkflowIdentifier("legacycli"), config)
}
