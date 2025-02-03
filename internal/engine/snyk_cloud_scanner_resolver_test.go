package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/snyk/cli-extension-iac/internal/cloudapi"
	"github.com/snyk/cli-extension-iac/internal/engine/mocks"
	"github.com/snyk/policy-engine/pkg/models"
	"github.com/snyk/policy-engine/pkg/policy"
	"github.com/stretchr/testify/require"
)

func TestSnykCloudResourceResolver_getAWSCloudResources(t *testing.T) {
	type args struct {
		query policy.ResourcesQuery
	}
	tests := []struct {
		name            string
		region          string
		args            args
		clientResp      []cloudapi.ResourceObject
		clientRespError error
		want            policy.ResourcesResult
		errMsg          string
	}{
		{
			name:   "Calling with wildcard region scope",
			region: "us-east-1",
			args: args{query: policy.ResourcesQuery{
				ResourceType: "sometype",
				Scope: map[string]string{
					"region": "*",
					"cloud":  "aws",
				},
			}},
			clientResp: []cloudapi.ResourceObject{
				{
					ID:   "id",
					Type: "sometype",
				},
			},
			want: policy.ResourcesResult{
				ScopeFound: true,
				Resources: []models.ResourceState{
					{
						Id:           "id",
						ResourceType: "sometype",
					},
				},
			},
		},
		{
			name:   "Calling with wrong region scope",
			region: "us-east-1",
			args: args{query: policy.ResourcesQuery{
				ResourceType: "sometype",
				Scope: map[string]string{
					"region": "us-east-2",
					"cloud":  "aws",
				},
			}},
			want: policy.ResourcesResult{
				ScopeFound: false,
			},
		},

		{
			name: "Calling with wrong cloud scope",
			args: args{query: policy.ResourcesQuery{
				ResourceType: "sometype",
				Scope: map[string]string{
					"region": "*",
					"cloud":  "google",
				},
			}},
			want: policy.ResourcesResult{
				ScopeFound: false,
			},
		},
		{
			name:   "when client error are returned",
			region: "us-east-1",
			args: args{query: policy.ResourcesQuery{
				ResourceType: "sometype",
				Scope: map[string]string{
					"region": "*",
					"cloud":  "aws",
				},
			}},
			clientRespError: errors.New("Dummy error"),
			want:            policy.ResourcesResult{ScopeFound: false},
			errMsg:          "Dummy error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockery := gomock.NewController(t)
			defer mockery.Finish()

			mockSnykClient := mocks.NewMocksnykCloudApiClient(mockery)
			c := &snykCloudResourceResolver{
				"environementID",
				mockSnykClient,
				"orgID",
			}

			mockSnykClient.EXPECT().Resources(context.TODO(), "orgID", "environementID", tt.args.query.ResourceType, "cloud").Return(tt.clientResp, tt.clientRespError).AnyTimes()
			got, err := c.getAWSCloudResources(context.TODO(), tt.args.query)
			if tt.errMsg != "" {
				require.EqualError(t, err, tt.errMsg)
			}
			require.Equal(t, tt.want, got)
		})
	}
}
