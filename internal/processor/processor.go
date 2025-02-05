package processor

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/snyk/cli-extension-iac/internal/ignore"
	"github.com/snyk/cli-extension-iac/internal/platform"
	engine "github.com/snyk/cli-extension-iac/internal/policyengine"
	"github.com/snyk/cli-extension-iac/internal/results"

	"github.com/snyk/cli-extension-iac/internal/settings"
)

type SnykPlatform interface {
	ShareResults(ctx context.Context, engineResults *engine.Results, opts platform.ShareResultsOptions) (*platform.ShareResultsOutput, error)
	ShareResultsRegistry(ctx context.Context, engineResults *results.Results, opts platform.ShareResultsOptions, policyFile string) (*platform.ShareResultsOutput, error)
}

type SettingsReader interface {
	ReadSettings(ctx context.Context) (*settings.Settings, error)
}

type ResultsProcessor struct {
	SnykPlatform                 SnykPlatform
	Report                       bool
	SeverityThreshold            string
	TargetReference              string
	TargetName                   string
	RemoteRepoUrl                string
	GetWd                        func() (string, error)
	GetRepoRootDir               func(string) (string, error)
	GetOriginUrl                 func(string) (string, error)
	SerializeEngineResults       func(results *engine.Results) (string, error)
	SettingsReader               SettingsReader
	PolicyPath                   string
	IncludePassedVulnerabilities bool
	IacNewEngine                 bool
	AllowAnalytics               bool
	Logger                       *zerolog.Logger
}

const IacV2TargetFile = "Infrastructure_as_code_issues"

func (p *ResultsProcessor) ProcessResults(rawResults *engine.Results, scanAnalytics results.ScanAnalytics) (*results.Results, error) {
	if rawResults == nil {
		return nil, nil
	}

	userSettings, err := p.SettingsReader.ReadSettings(context.Background())
	if err != nil {
		return nil, fmt.Errorf("read settings: %v", err)
	}

	projectName, err := p.computeProjectName()
	if err != nil {
		return nil, fmt.Errorf("compute project name: %v", err)
	}

	sourceURI, err := p.computeProjectURL()
	if err != nil {
		return nil, fmt.Errorf("compute project URI: %v", err)
	}

	matcher, err := p.createIgnoreMatcher()
	if err != nil {
		return nil, fmt.Errorf("create ignore policy matcher: %v", err)
	}

	if len(userSettings.CustomSeverities) != 0 {
		rawResults = applyCustomSeverities(rawResults, userSettings.CustomSeverities)
	}

	rawResults = filterMissingResources(rawResults)
	scanResults := results.FromEngineResults(rawResults, p.IncludePassedVulnerabilities)
	scanResults.Metadata.ProjectName = projectName

	if p.SeverityThreshold != "" {
		scanResults = filterBySeverityThreshold(scanResults, p.SeverityThreshold)
	}

	scanResults = filterVulnerabilitiesByIgnores(scanResults, matcher, time.Now())
	scanResults.ScanAnalytics = scanAnalytics

	if p.Report {
		p.Logger.Info().Msgf("share results: project name = %v", projectName)
		p.Logger.Info().Msgf("share results: source URI = %v", sourceURI)

		opts := platform.ShareResultsOptions{
			OrgPublicID:    userSettings.OrgPublicID,
			Kind:           "cli",
			Name:           projectName,
			Branch:         p.TargetReference,
			SourceURI:      sourceURI,
			SourceType:     "cli",
			AllowAnalytics: p.AllowAnalytics,
		}

		if p.IacNewEngine {
			policyFile, err := p.readPolicyFile()
			if err != nil {
				return nil, fmt.Errorf("share results to Registry failed on reading the policy file: %v", err)
			}

			shareResults := results.FromEngineResults(rawResults, false)

			output, err := p.SnykPlatform.ShareResultsRegistry(context.Background(), shareResults, opts, string(policyFile))
			if err != nil {
				return nil, fmt.Errorf("share results: %v", err)
			}

			// add the created project public id to the scan result to be shown in the cli response
			scanResults.Metadata.ProjectPublicId = output.ProjectIds[IacV2TargetFile]
		} else {
			shareResult, err := p.SnykPlatform.ShareResults(context.Background(), rawResults, opts)
			if err != nil {
				return nil, fmt.Errorf("share results: %v", err)
			}
			p.Logger.Info().Msgf("share results: report URI = %s", shareResult.URL)
		}
	}

	return scanResults, nil
}

func (p *ResultsProcessor) createIgnoreMatcher() (*ignore.Matcher, error) {
	data, err := p.readPolicyFile()
	if err != nil {
		return nil, err
	}

	return ignore.NewMatcherFromPolicy(data)
}

func (p *ResultsProcessor) readPolicyFile() ([]byte, error) {
	if p.PolicyPath == "" {
		return nil, nil
	}

	data, err := os.ReadFile(p.PolicyPath)
	if os.IsNotExist(err) {
		return nil, nil
	}

	return data, err
}
