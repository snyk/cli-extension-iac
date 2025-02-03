package processor

import (
	"github.com/snyk/cli-extension-iac/internal/engine"
	"github.com/snyk/cli-extension-iac/internal/results"
	"github.com/snyk/policy-engine/pkg/postprocess"
)

const (
	severityLevelLow = iota
	severityLevelMedium
	severityLevelHigh
	severityLevelCritical
)

var severityLevelByName = map[string]int{
	"low":      severityLevelLow,
	"medium":   severityLevelMedium,
	"high":     severityLevelHigh,
	"critical": severityLevelCritical,
}

func filterBySeverityThreshold(scanResults *results.Results, severityThreshold string) *results.Results {
	if scanResults == nil {
		return nil
	}

	severityThresholdLevel := severityLevelByName[severityThreshold]

	var filteredVulnerabilities []results.Vulnerability

	for _, vulnerability := range scanResults.Vulnerabilities {
		severityLevel, ok := severityLevelByName[vulnerability.Severity]
		if !ok {
			continue
		}
		if severityLevel >= severityThresholdLevel {
			filteredVulnerabilities = append(filteredVulnerabilities, vulnerability)
		}
	}

	scanResults.Vulnerabilities = filteredVulnerabilities

	return scanResults
}

func applyCustomSeverities(rawResults *engine.Results, customSeverities map[string]string) *engine.Results {
	if rawResults == nil {
		return nil
	}

	postprocess.ApplyCustomSeverities(rawResults, customSeverities)

	return rawResults
}
