package iactest

import (
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
	"log"
	"os"
	"testing"
)

func TestValidateFlagValue(t *testing.T) {
	type testInput struct {
		flagName  string
		flagValue string
		flag      flagWithValues
	}

	testCases := []struct {
		in     testInput
		hasErr bool
		desc   string
	}{
		{
			in: testInput{
				flagName:  FlagProjectEnvironment,
				flagValue: "backend",
				flag: flagWithValues{
					name:        FlagProjectEnvironment,
					validValues: map[string]struct{}{"backend": {}, "frontend": {}},
					allowEmpty:  true,
				},
			},
			hasErr: false,
			desc:   "valid flag",
		},
		{
			in: testInput{
				flagName:  FlagProjectEnvironment,
				flagValue: "backend,backend",
				flag: flagWithValues{
					name:        FlagProjectEnvironment,
					validValues: map[string]struct{}{"backend": {}, "frontend": {}},
					allowEmpty:  true,
				},
			},
			hasErr: false,
			desc:   "multiple valid flags",
		},
		{
			in: testInput{
				flagName:  FlagProjectEnvironment,
				flagValue: "",
				flag: flagWithValues{
					name:        FlagProjectEnvironment,
					validValues: map[string]struct{}{"backend": {}, "frontend": {}},
					allowEmpty:  true,
				},
			},
			hasErr: false,
			desc:   "valid empty flag",
		},
		{
			in: testInput{
				flagName:  FlagProjectEnvironment,
				flagValue: "",
				flag: flagWithValues{
					name:        FlagProjectEnvironment,
					validValues: map[string]struct{}{"backend": {}, "frontend": {}},
					allowEmpty:  false,
				},
			},
			hasErr: true,
			desc:   "invalid empty flag",
		},
		{
			in: testInput{
				flagName:  FlagProjectEnvironment,
				flagValue: "invalid-value",
				flag: flagWithValues{
					name:        FlagProjectEnvironment,
					validValues: map[string]struct{}{"backend": {}, "frontend": {}},
					allowEmpty:  true,
				},
			},
			hasErr: true,
			desc:   "invalid flag",
		},
		{
			in: testInput{
				flagName:  FlagProjectEnvironment,
				flagValue: "invalid-value!tc=,",
				flag: flagWithValues{
					name:        FlagProjectEnvironment,
					validValues: map[string]struct{}{"backend": {}, "frontend": {}},
					allowEmpty:  true,
				},
			},
			hasErr: true,
			desc:   "invalid flag format",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			config := configuration.New()
			config.Set(tc.in.flagName, tc.in.flagValue)

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
	type testInput struct {
		flagTagsIsSet        bool
		flagProjectTagsIsSet bool
		flagReport           bool
		flagValue            string
	}

	testCases := []struct {
		in     testInput
		hasErr bool
		desc   string
	}{
		{
			in: testInput{
				flagTagsIsSet:        true,
				flagProjectTagsIsSet: true,
				flagReport:           true,
				flagValue:            "",
			},
			hasErr: true,
			desc:   "invalid: cant have both --tags and --project-tags set",
		},
		{
			in: testInput{
				flagTagsIsSet:        true,
				flagProjectTagsIsSet: false,
				flagReport:           false,
				flagValue:            "",
			},
			hasErr: true,
			desc:   "invalid: --report is not true",
		},
		{
			in: testInput{
				flagTagsIsSet:        false,
				flagProjectTagsIsSet: false,
				flagReport:           false,
				flagValue:            "",
			},
			hasErr: false,
			desc:   "no --tags or --project-tags set, no validation needed",
		},
		{
			in: testInput{
				flagTagsIsSet:        true,
				flagProjectTagsIsSet: false,
				flagReport:           true,
				flagValue:            "env=dev,stage=first",
			},
			hasErr: false,
			desc:   "valid --tags",
		},
		{
			in: testInput{
				flagTagsIsSet:        false,
				flagProjectTagsIsSet: true,
				flagReport:           true,
				flagValue:            "env=dev,stage=first",
			},
			hasErr: false,
			desc:   "valid --project-tags",
		},
		{
			in: testInput{
				flagTagsIsSet:        true,
				flagProjectTagsIsSet: false,
				flagReport:           true,
				flagValue:            "",
			},
			hasErr: false,
			desc:   "valid empty --tags",
		},
		{
			in: testInput{
				flagTagsIsSet:        false,
				flagProjectTagsIsSet: true,
				flagReport:           true,
				flagValue:            "",
			},
			hasErr: false,
			desc:   "valid empty --project-tags",
		},
		{
			in: testInput{
				flagTagsIsSet:        true,
				flagProjectTagsIsSet: false,
				flagReport:           true,
				flagValue:            "env=dev,test",
			},
			hasErr: true,
			desc:   "invalid --tags",
		},
		{
			in: testInput{
				flagTagsIsSet:        false,
				flagProjectTagsIsSet: true,
				flagReport:           true,
				flagValue:            "env=dev,test-value",
			},
			hasErr: true,
			desc:   "invalid --project-tags",
		},
	}
	log.SetOutput(os.Stdout)
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			config := configuration.New()

			if tc.in.flagTagsIsSet {
				config.Set(FlagTags, tc.in.flagValue)
			}
			if tc.in.flagProjectTagsIsSet {
				config.Set(FlagProjectTags, tc.in.flagValue)
			}
			config.Set(FlagReport, tc.in.flagReport)

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
	type testInput struct {
		flagReportIsSet                     bool
		flagProjectEnvironmentIsSet         bool
		flagProjectLifecycleIsSet           bool
		flagProjectBusinessCriticalityIsSet bool
		flagTagsIsSet                       bool
		flagValue                           string
	}

	testCases := []struct {
		in     testInput
		hasErr bool
		desc   string
	}{
		{
			in: testInput{
				flagReportIsSet:                     false,
				flagProjectEnvironmentIsSet:         true,
				flagProjectLifecycleIsSet:           false,
				flagProjectBusinessCriticalityIsSet: false,
				flagValue:                           "backend",
			},
			hasErr: true,
			desc:   "invalid --project-environment, --report is not set",
		},
		{
			in: testInput{
				flagReportIsSet:                     false,
				flagProjectEnvironmentIsSet:         true,
				flagProjectLifecycleIsSet:           false,
				flagProjectBusinessCriticalityIsSet: false,
				flagValue:                           "production",
			},
			hasErr: true,
			desc:   "invalid --project-lifecycle, --report is not set",
		},
		{
			in: testInput{
				flagReportIsSet:                     false,
				flagProjectEnvironmentIsSet:         true,
				flagProjectLifecycleIsSet:           false,
				flagProjectBusinessCriticalityIsSet: false,
				flagValue:                           "low",
			},
			hasErr: true,
			desc:   "invalid --project-business-criticality, --report is not set",
		},
		{
			in: testInput{
				flagReportIsSet:                     false,
				flagProjectEnvironmentIsSet:         true,
				flagProjectLifecycleIsSet:           false,
				flagProjectBusinessCriticalityIsSet: false,
				flagValue:                           "low",
			},
			hasErr: true,
			desc:   "invalid --project-tags, --report is not set",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			config := configuration.New()
			if tc.in.flagProjectEnvironmentIsSet {
				config.Set(FlagProjectEnvironment, tc.in.flagValue)
			}
			if tc.in.flagProjectBusinessCriticalityIsSet {
				config.Set(FlagProjectBusinessCriticality, tc.in.flagValue)
			}
			if tc.in.flagProjectLifecycleIsSet {
				config.Set(FlagProjectLifecycle, tc.in.flagValue)
			}
			if tc.in.flagTagsIsSet {
				config.Set(FlagTags, tc.in.flagValue)
			}

			err := validateReportConfig(config)
			if tc.hasErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}
		})
	}

}
