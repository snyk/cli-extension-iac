package processor

import (
	"fmt"

	engine "github.com/snyk/cli-extension-iac/internal/policyengine"
)

func filterMissingResources(rawResults *engine.Results) *engine.Results {
	for i := range rawResults.Results {
		// for now we know that we can have missing resources only because we filtered them with the tfPlanFilter
		if rawResults.Results[i].Input.InputType != "tf_plan" {
			continue
		}

		// maybe we had only 1 resource that we filtered out as it had no-op
		if len(rawResults.Results[i].Input.Resources) == 0 {
			continue
		}

		resources := make(map[string]bool)
		for _, inResources := range rawResults.Results[i].Input.Resources {
			for _, inResource := range inResources {
				resources[composeResourceIdForComparison(inResource.ResourceType, inResource.Id, inResource.Namespace)] = true
			}
		}

		for _, ruleResults := range rawResults.Results[i].RuleResults {
			for j := range ruleResults.Results {
				_, ok := resources[composeResourceIdForComparison(ruleResults.Results[j].ResourceType, ruleResults.Results[j].ResourceId, ruleResults.Results[j].ResourceNamespace)]
				if !ok {
					for _, resource := range ruleResults.Results[j].Resources {
						_, ok2 := resources[composeResourceIdForComparison(resource.Type, resource.Id, resource.Namespace)]
						if ok2 {
							ruleResults.Results[j].ResourceType = resource.Type
							ruleResults.Results[j].ResourceId = resource.Id
							ruleResults.Results[j].ResourceNamespace = resource.Namespace
						}
					}
				}
			}
		}
	}

	return rawResults
}

func composeResourceIdForComparison(resourceType, resourceId, resourceNamespace string) string {
	return fmt.Sprintf("%s_%s_%s", resourceType, resourceId, resourceNamespace)
}
