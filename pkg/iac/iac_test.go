package iac_test

import (
	"net/url"
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-iac/internal/commands/iactest"
	"github.com/snyk/cli-extension-iac/pkg/iac"
)

func TestInit(t *testing.T) {
	c := configuration.New()
	e := workflow.NewWorkFlowEngine(c)

	err := e.Init()
	assert.NoError(t, err)

	err = iac.Init(e)
	assert.NoError(t, err)

	assertWorkflowExists(t, e, iactest.WorkflowID)
}

func assertWorkflowExists(t *testing.T, e workflow.Engine, id *url.URL) {
	t.Helper()

	wflw, ok := e.GetWorkflow(id)
	assert.True(t, ok)
	assert.NotNil(t, wflw)
}
