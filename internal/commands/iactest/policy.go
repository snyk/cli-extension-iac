package iactest

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/rs/zerolog"
)

// Preserves the original behavior for IaC+ in the CLI, found at:
// https://github.com/snyk/cli/blob/2051a6d38071a304dbef97784cfeac20c7f56d09/src/cli/commands/test/iac/v2/index.ts#L63
func GetPolicyFile(policyPathFlag string, rootDir string, logger *zerolog.Logger) string {
	policyPath, err := getPolicyFileAtPath(rootDir)
	if err != nil {
		logger.Debug().Err(err).Msg(".snyk policy not found in current working directory")
	}

	// --policy-path flag has precedence over the .snyk file in the root directory
	if policyPathFlag != "" {
		policyPath2, err := getPolicyFileAtPath(policyPathFlag)
		if err != nil {
			logger.Debug().Err(err).Msg(".snyk policy not found using --policy-path flag")
		} else {
			logger.Debug().Msgf("Using .snyk policy from --policy-path flag")
			return policyPath2
		}
	}

	if policyPath != "" {
		logger.Debug().Msgf("Using .snyk policy from current working directory")
	}
	return policyPath
}

func getPolicyFileAtPath(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("error for path %s: %v", path, err)
	}

	policyPath := filepath.Join(path, ".snyk")
	if !info.IsDir() {
		// if the path is a file, use the directory of the file
		policyPath = filepath.Join(filepath.Dir(path), ".snyk")
	}

	_, err = os.Stat(policyPath)
	if err != nil {
		return "", fmt.Errorf("error getting .snyk at path %s: %v", policyPath, err)
	}

	return policyPath, nil
}
