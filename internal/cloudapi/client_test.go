package cloudapi_test

import (
	"context"
	"net/http"
	"net/http/httputil"
	"os"
	"testing"

	"github.com/snyk/cli-extension-iac/internal/cloudapi"
	engine "github.com/snyk/cli-extension-iac/internal/policyengine"
	"github.com/spf13/afero"
)

// TestShareResults is an end-to-end test that runs the engine with a rules
// bundle, scans a path, and uploads the results using the "create scan" REST
// API. This test is only run if all the environment variables below are set.
// Otherwise, the test will be skipped.
func TestShareResults(t *testing.T) {
	var (
		api    = readEnv(t, "SNYK_API")
		org    = readEnv(t, "SNYK_ORG")
		bundle = readEnv(t, "SNYK_BUNDLE")
		path   = readEnv(t, "SNYK_PATH")
	)

	bundleReader, err := os.Open(bundle)
	if err != nil {
		t.Fatalf("open bundle: %v", err)
	}

	defer func() {
		if err := bundleReader.Close(); err != nil {
			t.Fatalf("close bundle: %v", err)
		}
	}()

	eng := engine.NewEngine(context.Background(), engine.EngineOptions{
		SnykBundle: bundleReader,
	})
	if err != nil {
		t.Fatalf("create engine: %v", err)
	}

	results, errs := eng.Run(context.Background(), engine.RunOptions{
		FS:    afero.NewOsFs(),
		Paths: []string{path},
	})
	if results == nil {
		t.Fatalf("no results returned: %v", errs)
	}

	httpClient := dumpClient{
		print:   t.Logf,
		wrapped: http.DefaultClient,
	}

	client := cloudapi.NewClient(cloudapi.ClientConfig{
		HTTPClient: httpClient,
		URL:        api,
		Version:    "2022-04-13~experimental",
	})

	artifacts, err := cloudapi.SerializeEngineResults(results)
	if err != nil {
		t.Fatalf("serialize engine results: %v", err)
	}

	createScanRequest := cloudapi.CreateScanRequest{
		Data: cloudapi.Data{
			Type: "scan",
			Attributes: cloudapi.Attributes{
				Kind:      "cli",
				Artifacts: artifacts,
				EnvironmentMetadata: cloudapi.EnvironmentMetadata{
					Name: "environment_name",
					Options: cloudapi.EnvironmentMetadataOptions{
						SourceURI:  "https://github.com/francescomari/foo",
						SourceType: "github",
					},
				},
			},
		},
	}

	if _, err := client.CreateScan(context.Background(), org, &createScanRequest, false); err != nil {
		t.Fatalf("create scan: %v", err)
	}
}

type mockHTTPClient struct {
	requests []*http.Request
	do       func(req *http.Request) (*http.Response, error)
}

func (c *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	c.requests = append(c.requests, req)
	return c.do(req)
}

func readEnv(t *testing.T, name string) string {
	value := os.Getenv(name)
	if value == "" {
		t.Skipf("environment variable %s not set", name)
	}
	return value
}

type dumpClient struct {
	print   func(string, ...any)
	wrapped cloudapi.HTTPClient
}

func (c dumpClient) Do(req *http.Request) (*http.Response, error) {
	if data, err := httputil.DumpRequest(req, true); err != nil {
		c.print("error: dump request: %v", err)
	} else {
		c.print("sending request:\n%s", string(data))
	}

	res, err := c.wrapped.Do(req)
	if err != nil {
		return nil, err
	}

	if data, err := httputil.DumpResponse(res, true); err != nil {
		c.print("error: dump response: %v", err)
	} else {
		c.print("received response:\n%s", string(data))
	}

	return res, nil
}
