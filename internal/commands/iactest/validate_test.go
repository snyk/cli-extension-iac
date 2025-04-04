package iactest

import (
	"os"
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
)

func TestValidateFlagValue(t *testing.T) {
	type testInput struct {
		config map[string]any
		flag   flagWithOptions
	}

	testCases := []struct {
		in     testInput
		hasErr bool
		desc   string
	}{
		{
			in: testInput{
				config: map[string]any{
					FlagProjectEnvironment: "backend",
				},
				flag: flagWithOptions{
					name:         FlagProjectEnvironment,
					validOptions: map[string]struct{}{"backend": {}, "frontend": {}},
					allowEmpty:   true,
				},
			},
			hasErr: false,
			desc:   "valid flag",
		},
		{
			in: testInput{
				config: map[string]any{
					FlagProjectEnvironment: "backend,backend",
				},
				flag: flagWithOptions{
					name:         FlagProjectEnvironment,
					validOptions: map[string]struct{}{"backend": {}, "frontend": {}},
					allowEmpty:   true,
				},
			},
			hasErr: false,
			desc:   "multiple valid flags",
		},
		{
			in: testInput{
				config: map[string]any{
					FlagProjectEnvironment: "",
				},
				flag: flagWithOptions{
					name:         FlagProjectEnvironment,
					validOptions: map[string]struct{}{"backend": {}, "frontend": {}},
					allowEmpty:   true,
				},
			},
			hasErr: false,
			desc:   "valid empty flag",
		},
		{
			in: testInput{
				config: map[string]any{
					FlagProjectEnvironment: "",
				},
				flag: flagWithOptions{
					name:         FlagProjectEnvironment,
					validOptions: map[string]struct{}{"backend": {}, "frontend": {}},
					allowEmpty:   false,
				},
			},
			hasErr: true,
			desc:   "invalid empty flag",
		},
		{
			in: testInput{
				config: map[string]any{
					FlagProjectEnvironment: "invalid-value",
				},
				flag: flagWithOptions{
					name:         FlagProjectEnvironment,
					validOptions: map[string]struct{}{"backend": {}, "frontend": {}},
					allowEmpty:   true,
				},
			},
			hasErr: true,
			desc:   "invalid flag",
		},
		{
			in: testInput{
				config: map[string]any{
					FlagProjectEnvironment: "invalid-value!tc=,",
				},
				flag: flagWithOptions{
					name:         FlagProjectEnvironment,
					validOptions: map[string]struct{}{"backend": {}, "frontend": {}},
					allowEmpty:   true,
				},
			},
			hasErr: true,
			desc:   "invalid flag format",
		},
		{
			in: testInput{
				config: map[string]any{
					FlagProjectEnvironment: "backend",
				},
				flag: flagWithOptions{
					name:         FlagProjectEnvironment,
					validOptions: map[string]struct{}{"backend": {}, "frontend": {}},
					allowEmpty:   true,
					singleChoice: true,
				},
			},
			hasErr: false,
			desc:   "valid flag with single choice",
		},
		{
			in: testInput{
				config: map[string]any{
					FlagProjectEnvironment: "backend,frontend",
				},
				flag: flagWithOptions{
					name:         FlagProjectEnvironment,
					validOptions: map[string]struct{}{"backend": {}, "frontend": {}},
					allowEmpty:   true,
					singleChoice: true,
				},
			},
			hasErr: true,
			desc:   "invalid flag with single choice",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			config := setupMockConfig(tc.in.config)

			err := validateFlagValue(config, tc.in.flag)
			if tc.hasErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func TestValidateTags(t *testing.T) {
	testCases := []struct {
		in     map[string]any
		hasErr bool
		desc   string
	}{
		{
			in:     map[string]any{},
			hasErr: false,
			desc:   "no --tags or --project-tags set, no validation needed",
		},
		{
			in: map[string]any{
				FlagProjectTags: "env=dev,stage=first",
			},
			hasErr: false,
			desc:   "valid --project-tags",
		},
		{
			in: map[string]any{
				FlagProjectTags: "",
			},
			hasErr: false,
			desc:   "valid empty --tags",
		},
		{
			in: map[string]any{
				FlagProjectTags: "env=dev,test",
			},
			hasErr: true,
			desc:   "invalid --project-tags",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			config := setupMockConfig(tc.in)

			err := validateTags(config)
			if tc.hasErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func TestValidateReportConfig(t *testing.T) {
	testCases := []struct {
		in     map[string]any
		hasErr bool
		desc   string
	}{
		{
			in: map[string]any{
				FlagProjectEnvironment: "invalid-env",
			},
			hasErr: true,
			desc:   "invalid --project-environment",
		},
		{
			in: map[string]any{
				FlagProjectLifecycle: "invalid-lifecycle",
			},
			hasErr: true,
			desc:   "invalid --project-lifecycle",
		},
		{
			in: map[string]any{
				FlagProjectBusinessCriticality: "invalid-business-criticality",
			},
			hasErr: true,
			desc:   "invalid --project-business-criticality",
		},
		{
			in: map[string]any{
				FlagProjectTags: "invalid-tags",
			},
			hasErr: true,
			desc:   "invalid --project-tags",
		},
		{
			in: map[string]any{
				FlagProjectTags:                "env=dev,stage=first",
				FlagProjectLifecycle:           "production",
				FlagProjectBusinessCriticality: "critical",
				FlagProjectEnvironment:         "backend",
			},
			hasErr: false,
			desc:   "valid --report options",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			config := setupMockConfig(tc.in)
			err := validateReportConfig(config)
			if tc.hasErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}
		})
	}

}

func TestValidateIacV2Config(t *testing.T) {
	testCases := []struct {
		in     map[string]any
		hasErr bool
		desc   string
	}{
		{
			in: map[string]any{
				FeatureFlagNewEngine:     true,
				FlagReport:               false,
				FlagSnykCloudEnvironment: "cloud",
			},
			hasErr: true,
			desc:   "invalid usage of --snyk-cloud-environment with iac v2",
		},
		{
			in: map[string]any{
				FeatureFlagNewEngine:   true,
				FlagReport:             true,
				FlagProjectEnvironment: "backend",
			},
			hasErr: false,
			desc:   "valid config with valid --report options",
		},
		{
			in: map[string]any{
				FeatureFlagNewEngine:   true,
				FlagReport:             false,
				FlagProjectEnvironment: "invalid-env",
			},
			hasErr: false,
			desc:   "valid config without --report, --project-environment is not checked",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			config := setupMockConfig(tc.in)

			err := validateIacV2Config(config)
			if tc.hasErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func TestValidateIacPlusConfig(t *testing.T) {
	testCases := []struct {
		in     map[string]any
		hasErr bool
		desc   string
	}{
		{
			in: map[string]any{
				FeatureFlagIntegratedExperience: true,
				FlagProjectEnvironment:          "backend",
			},
			hasErr: true,
			desc:   "invalid usage of --project-environment with iac+",
		},
		{
			in: map[string]any{
				FeatureFlagIntegratedExperience: true,
				FlagProjectLifecycle:            "development",
			},
			hasErr: true,
			desc:   "invalid usage of --project-lifecycle with iac+",
		},
		{
			in: map[string]any{
				FeatureFlagIntegratedExperience: true,
				FlagReport:                      false,
				FlagRemoteRepoURL:               "ref",
			},
			hasErr: false,
			desc:   "valid config without --report, --remote-repo-url is not checked",
		},
		{
			in: map[string]any{
				FeatureFlagIntegratedExperience: true,
				FlagReport:                      true,
				FlagRemoteRepoURL:               "ref",
			},
			hasErr: false,
			desc:   "valid config with valid --report options",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			config := setupMockConfig(tc.in)

			err := validateIacPlusConfig(config)
			if tc.hasErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func TestValidateConfig(t *testing.T) {
	testCases := []struct {
		in     map[string]any
		hasErr bool
		desc   string
	}{
		{
			in: map[string]any{
				FeatureFlagIntegratedExperience: true,
				FlagProjectEnvironment:          "backend",
			},
			hasErr: true,
			desc:   "invalid usage of --project-environment with iac+",
		},
		{
			in: map[string]any{
				FeatureFlagIntegratedExperience: true,
				FlagReport:                      true,
				FlagRemoteRepoURL:               "ref",
			},
			hasErr: false,
			desc:   "valid config with valid --report options for iac+",
		},
		{
			in: map[string]any{
				FeatureFlagNewEngine:     true,
				FlagReport:               false,
				FlagSnykCloudEnvironment: "cloud",
			},
			hasErr: true,
			desc:   "invalid usage of --snyk-cloud-environment with iac v2",
		},
		{
			in: map[string]any{
				FeatureFlagNewEngine:   true,
				FlagReport:             true,
				FlagProjectEnvironment: "backend",
			},
			hasErr: false,
			desc:   "valid config with valid --report options for iac v2",
		},
		{
			in: map[string]any{
				FeatureFlagNewEngine: true,
				FlagVarFile:          "test.txt",
			},
			hasErr: true,
			desc:   "invalid --var-file for iac v2",
		},
		{
			in: map[string]any{
				FeatureFlagIntegratedExperience: true,
				FlagVarFile:                     "test.txt",
			},
			hasErr: true,
			desc:   "invalid --var-file for iac+",
		},
		{
			in: map[string]any{
				FeatureFlagNewEngine: true,
				RulesClientURL:       "",
			},
			hasErr: true,
			desc:   "empty rules client URL for iac v2",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			config := setupMockConfig(tc.in)

			err := validateConfig(config)
			if tc.hasErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func TestValidateVarFile(t *testing.T) {
	type input struct {
		value  string
		exists bool
	}

	testCases := []struct {
		in     input
		hasErr bool
		desc   string
	}{
		{
			in:     input{"test.txt", true},
			hasErr: true,
			desc:   "invalid --var-file extension",
		},
		{
			in:     input{"test.tfvars", false},
			hasErr: true,
			desc:   "invalid --var-file, file does not exist",
		},
		{
			in:     input{"test.tfvars", true},
			hasErr: false,
			desc:   "valid --var-file",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			if tc.in.exists {
				_, err := os.Create(tc.in.value)
				if err != nil {
					t.Error(err)
				}
				defer os.Remove(tc.in.value)
			}

			config := setupMockConfig(map[string]any{FlagVarFile: tc.in.value})

			if tc.hasErr {
				assert.NotNil(t, validateVarFile(config))
			} else {
				assert.Nil(t, validateVarFile(config))
			}
		})
	}
}

func setupMockConfig(flagValues map[string]any) configuration.Configuration {
	config := configuration.New()
	config.Set(RulesClientURL, "url")

	for key, value := range flagValues {
		config.Set(key, value)
	}
	return config
}
