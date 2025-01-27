package main

import (
	"log"

	"github.com/snyk/cli-extension-iac/pkg/iac"

	"github.com/snyk/go-application-framework/pkg/devtools"
)

func main() {
	cmd, err := devtools.Cmd(iac.Init)
	if err != nil {
		log.Fatal(err)
	}
	cmd.SilenceUsage = true
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
