package results

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	engine "github.com/snyk/cli-extension-iac/internal/policyengine"
)

type Results struct {
	Resources             []Resource      `json:"resources,omitempty"`
	Vulnerabilities       []Vulnerability `json:"vulnerabilities,omitempty"`
	PassedVulnerabilities []Vulnerability `json:"passedVulnerabilities,omitempty"`
	Metadata              Metadata        `json:"metadata"`
	ScanAnalytics         ScanAnalytics   `json:"scanAnalytics"`
}

type Metadata struct {
	ProjectName     string `json:"projectName,omitempty"`
	ProjectPublicId string `json:"projectPublicId,omitempty"`
	IgnoredCount    int    `json:"ignoredCount"`
}

type Vulnerability struct {
	Rule        Rule                   `json:"rule"`
	Message     string                 `json:"message"`
	Remediation string                 `json:"remediation"`
	Severity    string                 `json:"severity"`
	Ignored     bool                   `json:"ignored"`
	Resource    Resource               `json:"resource"`
	Context     map[string]interface{} `json:"context,omitempty"`
}

type Rule struct {
	ID                      string   `json:"id"`
	Title                   string   `json:"title"`
	Description             string   `json:"description"`
	References              string   `json:"references,omitempty"`
	Labels                  []string `json:"labels,omitempty"`
	Category                string   `json:"category,omitempty"`
	Documentation           string   `json:"documentation,omitempty"`
	IsGeneratedByCustomRule bool     `json:"isGeneratedByCustomRule,omitempty"`
}

type Resource struct {
	ID            string            `json:"id"`
	Type          string            `json:"type"`
	Kind          string            `json:"kind"`
	Path          []any             `json:"path,omitempty"`
	FormattedPath string            `json:"formattedPath,omitempty"`
	File          string            `json:"file,omitempty"`
	Line          int               `json:"line,omitempty"`
	Column        int               `json:"column,omitempty"`
	Tags          map[string]string `json:"tags,omitempty"`
}

type ScanAnalytics struct {
	SuppressedResults map[string][]string `json:"suppressedResults,omitempty"`
}

// FromEngineResults converts the results produced by the engine to a flatter
// representation which is easier to filter and aggregate on.
func FromEngineResults(results *engine.Results, includePassed bool) *Results {
	if results == nil {
		return nil
	}

	failedVulnerabilities, passedVulnerabilities := vulnerabilitiesFromEngineResults(results, includePassed)

	return &Results{
		Resources:             resourcesFromEngineResults(results),
		Vulnerabilities:       failedVulnerabilities,
		PassedVulnerabilities: passedVulnerabilities,
	}
}

var inputKindByInputType = map[string]string{
	"tf":         "terraformconfig",
	"tf_hcl":     "terraformconfig",
	"tf-hcl":     "terraformconfig",
	"tf_plan":    "terraformconfig",
	"tf-plan":    "terraformconfig",
	"tf_state":   "terraformconfig",
	"tf-state":   "terraformconfig",
	"cloud_scan": "terraformconfig",
	"cloud-scan": "terraformconfig",
	"arm":        "armconfig",
	"k8s":        "k8sconfig",
	"cfn":        "cloudformationconfig",
}

func vulnerabilitiesFromEngineResults(results *engine.Results, includePassed bool) (failed []Vulnerability, passed []Vulnerability) {

	// The Policy Engine can return rule results associated to zero or more rules.
	// We only report vulnerabilities for rule results associated to at least one
	// resource, and only for the primary resource of the rule results.

	// Each rule result reports which resource is the primary one by providing the
	// primary resource's resource id, type and namespace. These three attributes
	// must be checked against the corresponding ones in each rule result's
	// resource to determine the primary resource in the rule result. In other
	// words, the identity of a resource is determined by its id, type and
	// namespace.

	// While this is not common, a resource might be vulnerable because of a bad
	// combination of multiple attribute. In this case, the vulnerable resource in
	// the rule result is be associated with more than one attribute. Because at
	// this point we don't how this information is going to be displayed, we
	// report more than one Vulnerability for the same resource, one for each
	// attribute. It's up to the user of this result to aggregate this information
	// appropriately.

	// Locations of a resource are represented as a stack, where the location of
	// the resource is the first element and the following elements are locations
	// of "container" resources. Therefore, if the location stack is not empty, we
	// only use the first element, which represents the location of the resource.

	// In addition to the failed vulnerabilities, we also report passed ones, see:
	// https://snyksec.atlassian.net/wiki/spaces/RD/pages/2049474952/Enrich+CLI+results+for+IaC+with+successful+items
	// https://snyksec.atlassian.net/browse/IAC-2969

	var vulnerabilitiesToAddTo *[]Vulnerability

	for _, result := range results.Results {
		for _, ruleResults := range result.RuleResults {
			for _, ruleResult := range ruleResults.Results {
				if ruleResult.Passed {
					if includePassed {
						vulnerabilitiesToAddTo = &passed
					} else {
						continue
					}
				} else {
					vulnerabilitiesToAddTo = &failed
				}

				var references string
				if len(ruleResults.References) > 0 {
					references = ruleResults.References[0].Url
				} else {
					references = ""
				}

				vulnerability := Vulnerability{
					Rule: Rule{
						ID:          ruleResults.Id,
						Title:       ruleResults.Title,
						Description: ruleResults.Description,
						Labels:      ruleResults.Labels,
						Category:    ruleResults.Category,
						References:  references,
					},
					Message:     ruleResult.Message,
					Remediation: ruleResult.Remediation,
					Severity:    ruleResult.Severity,
					Ignored:     ruleResult.Ignored,
					Context:     ruleResult.Context,
				}

				if isSnykRule(ruleResults.Id) {
					vulnerability.Rule.Documentation = "https://security.snyk.io/rules/cloud/" + ruleResults.Id
				} else {
					vulnerability.Rule.IsGeneratedByCustomRule = true
				}

				for _, resource := range ruleResult.Resources {
					if resource.Id != ruleResult.ResourceId ||
						resource.Type != ruleResult.ResourceType ||
						resource.Namespace != ruleResult.ResourceNamespace {
						continue
					}

					vulnerability.Resource = Resource{
						ID:   resource.Id,
						Type: resource.Type,
						Kind: kindFromInputType(result.Input.InputType),
					}

					if len(resource.Location) > 0 {
						location := resource.Location[0]
						vulnerability.Resource.File = location.Filepath
						vulnerability.Resource.Line = location.Line
						vulnerability.Resource.Column = location.Column
					}

					if result.Input.Resources != nil {
						if resourcesByType, typeExists := result.Input.Resources[resource.Type]; typeExists {
							if resourceDetails, idExists := resourcesByType[resource.Id]; idExists {
								vulnerability.Resource.Tags = resourceDetails.Tags
							}
						}
					}

					if len(resource.Attributes) == 0 {
						vulnerability.Resource.FormattedPath = formattedPath(ruleResults.Id, resource.Id, []any{})
						*vulnerabilitiesToAddTo = append(*vulnerabilitiesToAddTo, vulnerability)
						continue
					}

					attribute := resource.Attributes[0]

					vulnerability.Resource.Path = attribute.Path
					vulnerability.Resource.FormattedPath = formattedPath(ruleResults.Id, resource.Id, attribute.Path)

					if attribute.Location != nil {
						location := attribute.Location
						vulnerability.Resource.File = location.Filepath
						vulnerability.Resource.Line = location.Line
						vulnerability.Resource.Column = location.Column
					}

					*vulnerabilitiesToAddTo = append(*vulnerabilitiesToAddTo, vulnerability)
				}
			}
		}
	}

	return
}

func resourcesFromEngineResults(results *engine.Results) []Resource {
	var resources []Resource

	for _, result := range results.Results {
		for _, inputResources := range result.Input.Resources {
			for _, inputResource := range inputResources {
				resource := Resource{
					Kind: kindFromInputType(result.Input.InputType),
					ID:   inputResource.Id,
					Type: inputResource.ResourceType,
				}

				meta := readMeta(inputResource.Meta)

				if meta != nil && len(meta.Location) > 0 {
					location := meta.Location[0]
					resource.File = location.FilePath
					resource.Line = location.Line
					resource.Column = location.Column
				}

				resources = append(resources, resource)
			}
		}
	}

	return resources
}

func kindFromInputType(inputType string) string {
	if mapped, ok := inputKindByInputType[inputType]; ok {
		return mapped
	}
	return inputType
}

func isSnykRule(ruleID string) bool {
	return strings.HasPrefix(ruleID, "SNYK-")
}

type meta struct {
	Location []location
}

type location struct {
	FilePath string
	Line     int
	Column   int
}

func readMeta(input map[string]any) *meta {
	if input == nil {
		return nil
	}

	data, err := json.Marshal(input)
	if err != nil {
		return nil
	}

	var result meta

	if err := json.Unmarshal(data, &result); err != nil {
		return nil
	}

	return &result
}

var arrayIndexingRegexp = regexp.MustCompile(`\[\s*(\d+)\s*\]`)

// formattedPath formats the path so its backwards compatible with the line number logic in cloud-config-parser, ignores, Jira issues, and reporting
func formattedPath(ruleId string, resourceId string, paths []any) string {
	var parts []string = []string{}

	if requiresInputPrefix[ruleId] {
		// for some rules, it expects a format like input.resource.aws_s3_bucket not aws_s3_bucket
		parts = append(parts, "input.resource")
	} else {
		// for other rules, it expects a format like resource.aws_s3_bucket not aws_s3_bucket
		parts = append(parts, "resource")
	}

	// expects a format like resource.aws_s3_bucket not module.module_name.resource.aws_s3_bucket
	if strings.HasPrefix(resourceId, "module.") {
		// remove "module." prefix
		resourceId = resourceId[strings.Index(resourceId, ".")+1:]

		// remove the name of the module
		resourceId = resourceId[strings.Index(resourceId, ".")+1:]
	}

	// expects a format like resource.aws_s3_bucket[name] not aws_s3_bucket.name
	if strings.Contains(resourceId, ".") {
		idElems := strings.Split(resourceId, ".")
		resourceType := idElems[0]
		resourceName := idElems[1]
		// expects a format like resource.aws_s3_bucket[this["0"]] not resource.aws_s3_bucket[this[0]]
		resourceName = arrayIndexingRegexp.ReplaceAllString(resourceName, `["$1"]`)
		parts = append(parts, fmt.Sprintf(".%s[%s]", resourceType, resourceName))
	} else if resourceId != "" {
		// edge case just in case
		parts = append(parts, fmt.Sprintf(".%s", resourceId))
	}

	if len(paths) > 0 {
		for _, path := range paths {
			switch p := path.(type) {
			case int:
				parts = append(parts, fmt.Sprintf("[%d]", p))
			case float64:
				parts = append(parts, fmt.Sprintf("[%d]", int(p)))
			case float32:
				parts = append(parts, fmt.Sprintf("[%d]", int(p)))
			default:
				parts = append(parts, fmt.Sprintf(".%s", path))
			}
		}
	}

	return strings.Join(parts, "")
}

var requiresInputPrefix = map[string]bool{
	"SNYK-CC-TF-1":  true,
	"SNYK-CC-TF-2":  true,
	"SNYK-CC-TF-3":  true,
	"SNYK-CC-TF-4":  true,
	"SNYK-CC-TF-5":  true,
	"SNYK-CC-TF-6":  true,
	"SNYK-CC-TF-7":  true,
	"SNYK-CC-TF-8":  true,
	"SNYK-CC-TF-9":  true,
	"SNYK-CC-TF-10": true,
	"SNYK-CC-TF-11": true,
	"SNYK-CC-TF-12": true,
	"SNYK-CC-TF-13": true,
	"SNYK-CC-TF-14": true,
	"SNYK-CC-TF-15": true,
	"SNYK-CC-TF-16": true,
	"SNYK-CC-TF-17": true,
	"SNYK-CC-TF-18": true,
	"SNYK-CC-TF-19": true,
	"SNYK-CC-TF-45": true,
	"SNYK-CC-TF-46": true,
}
