package engine

import (
	"context"

	"github.com/snyk/cli-extension-iac/internal/cloudapi"

	"github.com/snyk/policy-engine/pkg/models"
	"github.com/snyk/policy-engine/pkg/policy"
)

//go:generate mockgen -source snyk_cloud_resource_resolver.go -package mocks -destination mocks/snyk_cloud_api_client.go snyk_cloud_api_client
type snykCloudApiClient interface {
	Resources(ctx context.Context, orgID, environementID, resourceType, resourceKind string) ([]cloudapi.ResourceObject, error)
}

type snykCloudResourceResolver struct {
	environementID string
	snykClient     snykCloudApiClient
	orgID          string
}

func (c *snykCloudResourceResolver) getAWSCloudResources(ctx context.Context, query policy.ResourcesQuery) (policy.ResourcesResult, error) {
	externalResourceScope := map[string]interface{}{
		"cloud":  "aws",
		"region": "*",
	}

	if !policy.ScopeMatches(query.Scope, externalResourceScope) {
		return policy.ResourcesResult{ScopeFound: false}, nil
	}
	if query.Scope["cloud"] != "aws" {
		return policy.ResourcesResult{ScopeFound: false}, nil
	}

	// get resources for environment filtered by type
	resources, err := c.snykClient.Resources(ctx, c.orgID, c.environementID, query.ResourceType, "cloud")
	if err != nil {
		return policy.ResourcesResult{}, err
	}

	// transform into resolver result
	res := policy.ResourcesResult{ScopeFound: true}
	for _, resource := range resources {
		attributes := resource.Attributes.State
		res.Resources = append(res.Resources, models.ResourceState{
			Id:           resource.ID,
			ResourceType: resource.Type,
			Attributes:   attributes,
		})
	}

	return res, nil
}
