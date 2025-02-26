package iactest

import (
	"github.com/snyk/go-application-framework/pkg/configuration"
)

type ProjectAttributes struct {
	ProjectEnvironment         *string
	ProjectBusinessCriticality *string
	ProjectLifecycle           *string
	ProjectTags                *string
}

func GetProjectAttributes(config configuration.Configuration) ProjectAttributes {
	projectAttributes := ProjectAttributes{}
	// if the flag is not set, we want to pass nil so we don't confuse this with the empty string value used for "unsetting" the flag
	projectAttributes.ProjectBusinessCriticality = getStringIfSet(config, FlagProjectBusinessCriticality)
	projectAttributes.ProjectLifecycle = getStringIfSet(config, FlagProjectLifecycle)
	projectAttributes.ProjectEnvironment = getStringIfSet(config, FlagProjectEnvironment)
	projectAttributes.ProjectTags = getStringIfSet(config, FlagProjectTags)

	return projectAttributes
}

func getStringIfSet(config configuration.Configuration, key string) *string {
	if config.IsSet(key) {
		v := config.GetString(key)
		return &v
	}
	return nil
}
