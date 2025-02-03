package settings_test

import (
	"context"
	"errors"
	"testing"

	"github.com/snyk/cli-extension-iac/internal/registry"
	"github.com/snyk/cli-extension-iac/internal/settings"
	"github.com/stretchr/testify/require"
)

type mockRegistryClient struct {
	readIACOrgSettings func(ctx context.Context, request registry.ReadIACOrgSettingsRequest) (*registry.ReadIACOrgSettingsResponse, error)
}

func (m mockRegistryClient) ReadIACOrgSettings(ctx context.Context, request registry.ReadIACOrgSettingsRequest) (*registry.ReadIACOrgSettingsResponse, error) {
	return m.readIACOrgSettings(ctx, request)
}

func TestReadSettingsError(t *testing.T) {
	client := mockRegistryClient{
		readIACOrgSettings: func(ctx context.Context, request registry.ReadIACOrgSettingsRequest) (*registry.ReadIACOrgSettingsResponse, error) {
			return nil, errors.New("error")
		},
	}

	reader := settings.Reader{
		RegistryClient: client,
		Org:            "org",
	}

	s, err := reader.ReadSettings(context.Background())

	require.Error(t, err)
	require.Nil(t, s)
}

func TestReadSettings(t *testing.T) {
	client := mockRegistryClient{
		readIACOrgSettings: func(ctx context.Context, request registry.ReadIACOrgSettingsRequest) (*registry.ReadIACOrgSettingsResponse, error) {
			require.Equal(t, "org", request.Org)

			response := registry.ReadIACOrgSettingsResponse{
				CustomPolicies: map[string]registry.CustomPolicy{
					"SNYK-CC-1": {
						Severity: "critical",
					},
				},
				Meta: registry.Meta{
					Org:         "org",
					OrgPublicId: "org-public-id",
					IgnoreSettings: registry.IgnoreSettings{
						AdminOnly:                  true,
						DisregardFilesystemIgnores: true,
						ReasonRequired:             true,
					},
				},
				Entitlements: map[string]bool{
					"infrastructureAsCode": true,
				},
			}

			return &response, nil
		},
	}

	reader := settings.Reader{
		RegistryClient: client,
		Org:            "org",
	}

	got, err := reader.ReadSettings(context.Background())

	require.Nil(t, err)

	expected := settings.Settings{
		Org:         "org",
		OrgPublicID: "org-public-id",
		CustomSeverities: settings.CustomSeverities{
			"SNYK-CC-1": "critical",
		},
		Entitlements: settings.Entitlements{
			InfrastructureAsCode: true,
		},
		IgnoreSettings: settings.IgnoreSettings{
			AdminOnly:                  true,
			DisregardFilesystemIgnores: true,
			ReasonRequired:             true,
		},
	}

	require.Equal(t, &expected, got)
}

func TestCachedReader(t *testing.T) {
	var clientCalls int

	client := mockRegistryClient{
		readIACOrgSettings: func(ctx context.Context, request registry.ReadIACOrgSettingsRequest) (*registry.ReadIACOrgSettingsResponse, error) {
			clientCalls++
			return nil, errors.New("error")
		},
	}

	reader := settings.Reader{
		RegistryClient: client,
		Org:            "org",
	}

	cached := settings.CachedReader{
		Reader: &reader,
	}

	_, _ = cached.ReadSettings(context.Background())
	_, _ = cached.ReadSettings(context.Background())

	require.Equal(t, 1, clientCalls)
}
