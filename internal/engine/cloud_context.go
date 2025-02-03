package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/snyk/policy-engine/pkg/models"
	"github.com/snyk/policy-engine/pkg/policy"

	"github.com/snyk/cli-extension-iac/internal/cloudapi"
	engine "github.com/snyk/cli-extension-iac/internal/policyengine"
)

func newResourcesResolvers(ctx context.Context, options RunOptions) (policy.ResourcesResolver, <-chan error, error) {
	var resolver policy.ResourcesResolver = nil
	var err error

	if options.SnykCloudEnvironment != "" {
		resolver, err = newSnykCloudScannerResourcesResolver(ctx, options.OrgPublicID, options.SnykCloudEnvironment, options.SnykClient)
		if err != nil {
			return nil, nil, err
		}
	}

	if resolver == nil {
		return nil, nil, nil
	}

	// We will only show the user the first cloud context error per scan
	resolverErrCh := make(chan error, 1)
	resolverWrapper := func(ctx context.Context, query policy.ResourcesQuery) (policy.ResourcesResult, error) {
		res, err := resolver(ctx, query)
		if err != nil {
			// If the channel buffer is full, better to throw away the errors than to
			// block forever
			select {
			case resolverErrCh <- Error{
				Message: fmt.Sprintf("An error occurred fetching cloud resources: %s", err),
				Code:    ErrorCodeResourcesResolverError,
			}:
			default:
			}
		}
		return res, err
	}
	return resolverWrapper, resolverErrCh, nil
}

func newSnykCloudScannerResourcesResolver(context context.Context, orgID, snykCloudEnvironmentID string, client cloudapi.Client) (policy.ResourcesResolver, error) {
	// get environment
	environments, err := client.Environments(context, orgID, snykCloudEnvironmentID)
	if err != nil {
		return nil, fmt.Errorf("Error searching for environment %s: %w", snykCloudEnvironmentID, err)
	}
	if len(environments) == 0 {
		return nil, fmt.Errorf("no environment %s", snykCloudEnvironmentID)
	}
	if len(environments) > 1 {
		// Is this possible ?
		return nil, fmt.Errorf("found more than one environment %s", snykCloudEnvironmentID)
	}
	// check kind
	environment := environments[0]
	environmentID := environment.ID

	if environment.Attributes.Kind != "aws" {
		// this check is to be changed when we support more than just aws rules for cloud context
		return nil, fmt.Errorf("unsupported environment %s (%s) (kind is %s)", environment.Attributes.Name, environmentID, environment.Attributes.Kind)
	}

	resolver := snykCloudResourceResolver{
		orgID:          orgID,
		environementID: environmentID,
		snykClient:     client,
	}
	return resolver.getAWSCloudResources, nil

}

// Suppressed results are a cloud context concept. When running with a cloud
// ResourcesResolver, certain rules that would have been flagged has the scan
// been static-only might have been suppressed. We first determine whether we
// need to make more policy evaluations, which can be done concurrently with the
// original evaluation. We await all result sets and derive the suppression
// data.
func awaitResultsAndGetSuppressions(eng *engine.Engine, ctx context.Context, options engine.RunOptions, inputs []models.State, originalResultsCh <-chan *engine.Results) (*engine.Results, map[string][]string) {
	// If we are not running with a ResourcesResolver, we don't need to run
	// another policy-engine. Just return the original results.
	if options.ResourcesResolver == nil {
		return <-originalResultsCh, nil
	}

	// Run the policy-engine again without a resolver so that we can compare
	// result sets, and find the suppressed results.
	options.ResourcesResolver = nil
	resultsWithoutResolver := <-evalInBackground(eng, ctx, options, inputs)
	originalResults := <-originalResultsCh

	return originalResults, calculateSuppressionInfo(originalResults, resultsWithoutResolver)
}

func calculateSuppressionInfo(withResolver, withoutResolver *models.Results) map[string][]string {
	// Leave as nil at first, so that it doesn't get serialised un-necessarily
	var suppressions map[string][]string

	for _, result := range withResolver.Results {
		for _, ruleAndResults := range result.RuleResults {
			for _, ruleResult := range ruleAndResults.Results {
				ruleResultWithoutResolver, found := findRuleResult(ruleAndResults.Id, ruleResult.ResourceId, result.Input, withoutResolver.Results)
				if found {
					passedOnlyWithResolver := ruleResult.Passed && !ruleResultWithoutResolver.Passed
					if !passedOnlyWithResolver {
						continue
					}

					if suppressions == nil {
						suppressions = map[string][]string{}
					}
					suppressions[ruleAndResults.Id] = append(suppressions[ruleAndResults.Id], ruleResult.ResourceId)
				}
			}
		}
	}
	return suppressions
}

func findRuleResult(ruleID, resourceID string, input models.State, results []models.Result) (models.RuleResult, bool) {
	for _, result := range results {
		if hash(result.Input.Meta) != hash(input.Meta) {
			continue
		}
		for _, ruleAndResults := range result.RuleResults {
			if ruleAndResults.Id != ruleID {
				continue
			}
			for _, ruleResult := range ruleAndResults.Results {
				if ruleResult.ResourceId != resourceID {
					continue
				}
				return ruleResult, true
			}
		}
	}
	return models.RuleResult{}, false
}

func hash(input interface{}) string {
	marshal, err := json.Marshal(input)
	if err != nil {
		panic(err)
	}
	sum256 := sha256.Sum256(marshal)
	return hex.EncodeToString(sum256[:])
}
