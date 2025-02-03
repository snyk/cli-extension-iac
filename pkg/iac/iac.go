package iac

import (
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-iac/internal/commands/iactest"
)

func Init(e workflow.Engine) error {
	// Register the "iac test" command
	if err := iactest.RegisterWorkflows(e); err != nil {
		return err
	}

	return nil
}
