package cloudapi_test

import (
	"context"
	_ "embed"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snyk/cli-extension-iac/internal/cloudapi"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/policy-engine/pkg/bundle"
	"github.com/snyk/policy-engine/pkg/bundle/base"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/multiple.tar
var multiple []byte

//go:embed testdata/empty.tar
var empty []byte

func TestGetCustomRules(t *testing.T) {
	tests := []struct {
		name          string
		resp          []byte
		expectedPath  string
		expectedInfos []base.SourceInfo
	}{
		{
			name:         "multiple bundles",
			resp:         multiple,
			expectedPath: "/hidden/orgs/org-id/cloud/custom_rules",
			expectedInfos: []base.SourceInfo{
				{
					SourceType: bundle.ARCHIVE,
					FileInfo: base.FileInfo{
						Path:     "./complete.tar.gz",
						Checksum: "e523e33765084f5bf60bf513c91cf279fecf93690be7c2939cf900ca02d77925",
					},
				},
				{
					SourceType: bundle.ARCHIVE,
					FileInfo: base.FileInfo{
						Path:     "./minimal.tar.gz",
						Checksum: "8c9a2ae238a8d23181cad33b091f29f467d2ce044dfe2e7b4951c380394e61d8",
					},
				},
			},
		},
		{
			name:          "empty",
			resp:          empty,
			expectedPath:  "/hidden/orgs/org-id/cloud/custom_rules",
			expectedInfos: []base.SourceInfo{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, tt.expectedPath, r.URL.Path)
				require.Equal(t, http.MethodGet, r.Method)
				require.Equal(t, "2022-12-21~beta", r.URL.Query().Get("version"))
				require.Equal(t, "application/octet-stream", r.Header.Get("Accept"))

				_, err := w.Write(tt.resp)
				require.NoError(t, err)
			}))

			defer server.Close()

			client := cloudapi.NewClient(cloudapi.ClientConfig{
				HTTPClient: server.Client(),
				URL:        server.URL,
				Version:    "1.2.3",
			})

			bundles, err := client.CustomRules(context.Background(), "org-id")
			require.NoError(t, err)

			infos := make([]base.SourceInfo, len(bundles))
			for idx, b := range bundles {
				infos[idx] = b.Info()
			}

			require.Equal(t, tt.expectedInfos, infos)
		})
	}
}

func TestGetCustomRulesNewApi(t *testing.T) {
	tests := []struct {
		name          string
		resp          []byte
		expectedPath  string
		expectedInfos []base.SourceInfo
	}{
		{
			name:         "multiple bundles",
			resp:         multiple,
			expectedPath: "/hidden/orgs/org-id/cloud/rule_bundles",
			expectedInfos: []base.SourceInfo{
				{
					SourceType: bundle.ARCHIVE,
					FileInfo: base.FileInfo{
						Path:     "./complete.tar.gz",
						Checksum: "e523e33765084f5bf60bf513c91cf279fecf93690be7c2939cf900ca02d77925",
					},
				},
				{
					SourceType: bundle.ARCHIVE,
					FileInfo: base.FileInfo{
						Path:     "./minimal.tar.gz",
						Checksum: "8c9a2ae238a8d23181cad33b091f29f467d2ce044dfe2e7b4951c380394e61d8",
					},
				},
			},
		},
		{
			name:          "empty",
			resp:          empty,
			expectedPath:  "/hidden/orgs/org-id/cloud/rule_bundles",
			expectedInfos: []base.SourceInfo{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, tt.expectedPath, r.URL.Path)
				require.Equal(t, http.MethodGet, r.Method)
				require.Equal(t, "2024-09-24~beta", r.URL.Query().Get("version"))
				require.Equal(t, "application/octet-stream", r.Header.Get("Accept"))

				_, err := w.Write(tt.resp)
				require.NoError(t, err)
			}))

			defer server.Close()

			client := cloudapi.NewClient(cloudapi.ClientConfig{
				HTTPClient:   server.Client(),
				URL:          server.URL,
				Version:      "1.2.3",
				IacNewEngine: true,
			})

			bundles, err := client.CustomRules(context.Background(), "org-id")
			require.NoError(t, err)

			infos := make([]base.SourceInfo, len(bundles))
			for idx, b := range bundles {
				infos[idx] = b.Info()
			}

			require.Equal(t, tt.expectedInfos, infos)
		})
	}
}

func TestGetCustomRulesInternal(t *testing.T) {
	tests := []struct {
		name          string
		resp          []byte
		expectedPath  string
		expectedInfos []base.SourceInfo
	}{
		{
			name:         "multiple bundles",
			resp:         multiple,
			expectedPath: "/internal/orgs/org-id/cloud/custom_rules",
			expectedInfos: []base.SourceInfo{
				{
					SourceType: bundle.ARCHIVE,
					FileInfo: base.FileInfo{
						Path:     "./complete.tar.gz",
						Checksum: "e523e33765084f5bf60bf513c91cf279fecf93690be7c2939cf900ca02d77925",
					},
				},
				{
					SourceType: bundle.ARCHIVE,
					FileInfo: base.FileInfo{
						Path:     "./minimal.tar.gz",
						Checksum: "8c9a2ae238a8d23181cad33b091f29f467d2ce044dfe2e7b4951c380394e61d8",
					},
				},
			},
		},
		{
			name:          "empty",
			resp:          empty,
			expectedPath:  "/internal/orgs/org-id/cloud/custom_rules",
			expectedInfos: []base.SourceInfo{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, tt.expectedPath, r.URL.Path)
				require.Equal(t, http.MethodGet, r.Method)
				require.Equal(t, "2022-12-21~beta", r.URL.Query().Get("version"))
				require.Equal(t, "application/octet-stream", r.Header.Get("Accept"))

				_, err := w.Write(tt.resp)
				require.NoError(t, err)
			}))

			defer server.Close()

			client := cloudapi.NewClient(cloudapi.ClientConfig{
				HTTPClient: server.Client(),
				URL:        server.URL,
				Version:    "1.2.3",
			})

			bundles, err := client.CustomRulesInternal(context.Background(), "org-id")
			require.NoError(t, err)

			infos := make([]base.SourceInfo, len(bundles))
			for idx, b := range bundles {
				infos[idx] = b.Info()
			}

			require.Equal(t, tt.expectedInfos, infos)
		})
	}
}

type mockRoundTripper struct {
	err error
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, m.err
}

func TestCustomRulesErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected error
	}{
		{
			name: "forbidden",
			err: snyk_errors.Error{
				StatusCode: http.StatusForbidden,
				Detail:     "forbidden details",
			},
			expected: cloudapi.ErrForbidden,
		},
		{
			name: "unauthorized",
			err: snyk_errors.Error{
				StatusCode: http.StatusUnauthorized,
				Detail:     "unauthorized details",
			},
			expected: errors.New("invalid status code: 401, details: unauthorized details"),
		},
		{
			name: "not found",
			err: snyk_errors.Error{
				StatusCode: http.StatusNotFound,
				Detail:     "not found details",
			},
			expected: errors.New("invalid status code: 404, details: not found details"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &http.Client{
				Transport: &mockRoundTripper{
					err: tt.err,
				},
			}

			client := cloudapi.NewClient(cloudapi.ClientConfig{
				HTTPClient: mockClient,
				URL:        "http://dummy-url",
				Version:    "version",
			})

			_, err := client.CustomRules(context.Background(), "org-id")
			require.EqualError(t, err, tt.expected.Error())

			_, err = client.CustomRulesInternal(context.Background(), "org-id")
			require.EqualError(t, err, tt.expected.Error())
		})
	}
}
