package rules

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"text/template"

	"github.com/stretchr/testify/require"
)

//go:embed testdata/versions.tpl.json
var versions string

//go:embed testdata/bundle.tar.gz
var bundle []byte

func bundleChecksum() string {
	hash := sha256.New()
	hash.Write(bundle)
	return hex.EncodeToString(hash.Sum(nil))
}

func TestRules_DownloadLatestBundle(t *testing.T) {
	tests := sharedTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			preferredBundleVersion := "v0.3.5"
			var server *httptest.Server

			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeVersionsMock(w, r, server, preferredBundleVersion)
				if r.URL.Path == "/cli/iac/rules/"+tt.expectedBundleVersion+"/bundle.tar.gz" {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write(bundle)
				}
			}))
			defer server.Close()

			rulesClient := &Client{
				HTTPClient: server.Client(),
				URL:        server.URL,
			}

			var b bytes.Buffer
			require.NoError(t, rulesClient.DownloadLatestBundle(tt.currentEngineVersion, &b))
			require.Equal(t, bundle, b.Bytes())

		})
	}
}

func TestRules_GetCompatibleBundleVersion(t *testing.T) {
	tests := sharedTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			preferredBundleVersion := "v0.3.5"
			var server *httptest.Server

			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeVersionsMock(w, r, server, preferredBundleVersion)
			}))
			defer server.Close()

			rulesClient := &Client{
				HTTPClient: server.Client(),
				URL:        server.URL,
			}

			bundleVersion, err := rulesClient.GetCompatibleBundleVersion(tt.currentEngineVersion)
			require.NoError(t, err)
			require.Equal(t, tt.expectedBundleVersion, bundleVersion)
		})
	}
}

func TestRules_DownloadLatestBundle_Failure(t *testing.T) {
	tests := []struct {
		name                   string
		preferredBundleVersion string
		currentEngineVersion   string
	}{
		{
			name:                   "bundle does not exist in S3",
			preferredBundleVersion: "non-existent-version",
			currentEngineVersion:   "0.4.0",
		},
		{
			name:                   "can't find any compatible version for a bundle, fails entirely",
			preferredBundleVersion: "v0.3.5",
			currentEngineVersion:   "0.1.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeVersionsMock(w, r, server, tt.preferredBundleVersion)
			}))
			defer server.Close()

			rulesClient := &Client{
				HTTPClient: server.Client(),
				URL:        server.URL,
			}

			var b bytes.Buffer
			err := rulesClient.DownloadLatestBundle(tt.currentEngineVersion, &b)
			require.Error(t, err)
			require.Zero(t, b.Len(), "file size should be 0")
		})
	}
}

func TestRules_DownloadPinnedBundle(t *testing.T) {
	var server *httptest.Server
	bundleVersion := "v0.2.0-dev.20221007"

	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeVersionsMock(w, r, server, bundleVersion)
		if r.URL.Path == "/cli/iac/rules/"+bundleVersion+"/bundle.tar.gz" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(bundle)
		}
	}))
	defer server.Close()

	rulesClient := &Client{
		HTTPClient: server.Client(),
		URL:        server.URL,
	}

	var b bytes.Buffer

	require.NoError(t, rulesClient.DownloadPinnedBundle(bundleVersion, "v0.4.0", &b))
	require.Equal(t, bundle, b.Bytes())
}

// If bundle version is bigger than PE version, but min required PE version is <= PE version
// then we should not have any error and the download should work
func TestRules_DownloadPinnedBundle_Regression_IAC_2958(t *testing.T) {
	var server *httptest.Server
	bundleVersion := "v0.31.0"

	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeVersionsMock(w, r, server, bundleVersion)
		if r.URL.Path == "/cli/iac/rules/"+bundleVersion+"/bundle.tar.gz" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(bundle)
		}
	}))
	defer server.Close()

	rulesClient := &Client{
		HTTPClient: server.Client(),
		URL:        server.URL,
	}

	var b bytes.Buffer

	require.NoError(t, rulesClient.DownloadPinnedBundle("v0.31.0", "v0.30.11", &b))
	require.Equal(t, bundle, b.Bytes())
}

func TestRules_DownloadBundle_S3_Failure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	rulesClient := &Client{
		HTTPClient: server.Client(),
		URL:        server.URL,
	}

	var b bytes.Buffer
	err := rulesClient.DownloadLatestBundle("", &b)
	require.Error(t, err)
	require.Zero(t, b.Len(), "file size should be 0")
}

func writeVersionsMock(w http.ResponseWriter, r *http.Request, server *httptest.Server, preferredBundleVersion string) {
	if r.URL.Path == "/versions.json" {
		w.WriteHeader(http.StatusOK)

		_ = template.Must(template.New("").Parse(versions)).Execute(w, map[string]any{
			"serverURL":        server.URL,
			"preferredVersion": preferredBundleVersion,
			"checksum":         bundleChecksum(),
		})
	}
}

func sharedTestCases() []struct {
	name                  string
	currentEngineVersion  string
	expectedBundleVersion string
} {
	return []struct {
		name                  string
		currentEngineVersion  string
		expectedBundleVersion string
	}{{
		name:                  "PE version compatible for latest rule bundle",
		currentEngineVersion:  "v0.4.1",
		expectedBundleVersion: "v0.3.5",
	},
		{
			name:                  "PE version not compatible for latest rule bundle, falls to latest compatible version",
			currentEngineVersion:  "v0.4.0",
			expectedBundleVersion: "v0.2.5-dev.20221013",
		}}
}
