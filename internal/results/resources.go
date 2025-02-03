package results

import (
	engine "github.com/snyk/cli-extension-iac/internal/policyengine"
	"github.com/snyk/policy-engine/pkg/models"
)

func StubResources(results *engine.Results) *engine.Results {
	if results == nil {
		return results
	}

	stubbedResults := make([]models.Result, 0, len(results.Results))

	for _, r := range results.Results {
		stubbedResults = append(stubbedResults, stubResult(r))
	}

	copy := *results
	copy.Results = stubbedResults
	return &copy
}

func stubResult(r models.Result) models.Result {
	if kindFromInputType(r.Input.InputType) == "terraformconfig" {
		return r
	}

	stubbedInput := make(map[string]map[string]models.ResourceState)

	for kind, states := range r.Input.Resources {
		for id, state := range states {
			stubbedResourceState := stubResourceState(state)

			if stubbedInput[kind] == nil {
				stubbedInput[kind] = map[string]models.ResourceState{id: stubbedResourceState}
			} else {
				stubbedInput[kind][id] = stubbedResourceState
			}
		}
	}

	copy := r
	copy.Input.Resources = stubbedInput
	return copy
}

func stubResourceState(s models.ResourceState) models.ResourceState {
	copy := s
	copy.Attributes = nil
	return copy
}
