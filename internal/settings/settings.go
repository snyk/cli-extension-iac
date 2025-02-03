package settings

import (
	"context"
	"fmt"
	"sync"

	"github.com/snyk/cli-extension-iac/internal/registry"
)

type RegistryClient interface {
	ReadIACOrgSettings(ctx context.Context, request registry.ReadIACOrgSettingsRequest) (*registry.ReadIACOrgSettingsResponse, error)
}

type CustomSeverities map[string]string

type Entitlements struct {
	InfrastructureAsCode bool
}

type IgnoreSettings struct {
	AdminOnly                  bool
	DisregardFilesystemIgnores bool
	ReasonRequired             bool
}

type Settings struct {
	Org              string
	OrgPublicID      string
	CustomSeverities CustomSeverities
	Entitlements     Entitlements
	IgnoreSettings   IgnoreSettings
}

type Reader struct {
	RegistryClient RegistryClient
	Org            string
}

func (r *Reader) ReadSettings(ctx context.Context) (*Settings, error) {
	response, err := r.RegistryClient.ReadIACOrgSettings(ctx, registry.ReadIACOrgSettingsRequest{
		Org: r.Org,
	})
	if err != nil {
		return nil, fmt.Errorf("read IaC org settings: %v", err)
	}

	customSeverities := make(map[string]string)

	for rule, policy := range response.CustomPolicies {
		customSeverities[rule] = policy.Severity
	}

	entitlements := make(map[string]bool)

	if response.Entitlements != nil {
		entitlements = response.Entitlements
	}

	settings := Settings{
		Org:              response.Meta.Org,
		OrgPublicID:      response.Meta.OrgPublicId,
		CustomSeverities: customSeverities,
		Entitlements: Entitlements{
			InfrastructureAsCode: entitlements["infrastructureAsCode"],
		},
		IgnoreSettings: IgnoreSettings{
			AdminOnly:                  response.Meta.IgnoreSettings.AdminOnly,
			DisregardFilesystemIgnores: response.Meta.IgnoreSettings.DisregardFilesystemIgnores,
			ReasonRequired:             response.Meta.IgnoreSettings.ReasonRequired,
		},
	}

	return &settings, nil
}

type CachedReader struct {
	Reader *Reader

	once     sync.Once
	settings *Settings
	error    error
}

func (r *CachedReader) ReadSettings(ctx context.Context) (*Settings, error) {
	r.once.Do(func() {
		r.settings, r.error = r.Reader.ReadSettings(ctx)
	})

	return r.settings, r.error
}
