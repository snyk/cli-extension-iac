package rules

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"

	"github.com/hashicorp/go-version"
)

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type Client struct {
	HTTPClient HTTPClient
	URL        string
}

type manifest struct {
	PreferredVersion string                    `json:"preferred_version"`
	Versions         map[string]bundleMetadata `json:"versions"`
}

type bundleMetadata struct {
	Checksum               string `json:"checksum"`
	Url                    string `json:"url"`
	MinPolicyEngineVersion string `json:"min_policy_engine_version"`
	ReleaseDate            string `json:"release_date"`
}

func (c *Client) downloadManifest() (manifest, error) {
	var latestManifest manifest

	if err := c.downloadJSON(fmt.Sprintf("%s/versions.json", c.URL), &latestManifest); err != nil {
		return manifest{}, fmt.Errorf("download latestManifest: %v", err)
	}
	return latestManifest, nil
}

func (c *Client) DownloadLatestBundle(currentEngineVersion string, w io.Writer) (e error) {
	manifest, err := c.downloadManifest()
	if err != nil {
		return fmt.Errorf("download manifest: %v", err)
	}

	if err := c.downloadBundleForVersion(currentEngineVersion, manifest, w); err != nil {
		return fmt.Errorf("download bundle: %v", err)
	}
	return nil
}

func (c *Client) downloadBundleForVersion(currentEngineVersion string, manifest manifest, w io.Writer) (e error) {
	compatibleBundleVersion, err := determineBundleVersion(currentEngineVersion, manifest)
	if err != nil {
		return fmt.Errorf("determine bundle version: %v", err)
	}
	bundle := manifest.Versions[compatibleBundleVersion]

	hash := sha256.New()

	if err := c.download(io.MultiWriter(w, hash), bundle.Url); err != nil {
		return fmt.Errorf("download bundle: %v", err)
	}

	if checksum := hex.EncodeToString(hash.Sum(nil)); bundle.Checksum != checksum {
		return fmt.Errorf("invalid checksum: expected %v, got %v", bundle.Checksum, checksum)
	}
	return nil
}

func (c *Client) GetCompatibleBundleVersion(policyEngineVersion string) (string, error) {
	manifest, err := c.downloadManifest()
	if err != nil {
		return "", fmt.Errorf("download manifest: %v", err)
	}

	bundleVersion, err := determineBundleVersion(policyEngineVersion, manifest)
	if err != nil {
		return "", fmt.Errorf("determine bundle version: %v", err)
	}

	return bundleVersion, nil
}

func determineBundleVersion(currentEngineVersion string, manifest manifest) (string, error) {
	rulesPreferredVersion := manifest.PreferredVersion

	preferredVersionBundle, ok := manifest.Versions[rulesPreferredVersion]
	if !ok {
		return "", fmt.Errorf("no descriptor found for preferred version %s", manifest.PreferredVersion)
	}

	minEngineVersionForBundle := preferredVersionBundle.MinPolicyEngineVersion

	if isEngineCompatible(currentEngineVersion, minEngineVersionForBundle) {
		return rulesPreferredVersion, nil
	}

	sortedVersions := make([]*version.Version, 0, len(manifest.Versions)-1)

	for k := range manifest.Versions {
		if k == rulesPreferredVersion {
			continue
		}

		parsed, err := version.NewSemver(k)
		if err != nil {
			return "", fmt.Errorf("unable to parse %s: %v", k, err)
		}

		sortedVersions = append(sortedVersions, parsed)
	}
	sort.Sort(sort.Reverse(version.Collection(sortedVersions)))

	for _, v := range sortedVersions {
		keyWithPrefix := "v" + v.String()
		if isEngineCompatible(currentEngineVersion, manifest.Versions[keyWithPrefix].MinPolicyEngineVersion) {
			return keyWithPrefix, nil
		}
	}
	return "", fmt.Errorf("no compatible rules bundle found for policy-engine version %v", currentEngineVersion)
}

func isEngineCompatible(currentVersion string, minimumVersion string) bool {
	curV, _ := version.NewVersion(currentVersion)
	minV, _ := version.NewVersion(minimumVersion)

	return curV.GreaterThanOrEqual(minV)
}

// DownloadPinnedBundle this function can be used if there is only a special need to pin a specific rules bundle version
func (c *Client) DownloadPinnedBundle(pinnedBundleVersion string, currentEngineVersion string, w io.Writer) (e error) {
	manifest, err := c.downloadManifest()
	if err != nil {
		return fmt.Errorf("download manifest: %v", err)
	}
	versionMap, ok := manifest.Versions[pinnedBundleVersion]
	minEngineVersionForBundle := versionMap.MinPolicyEngineVersion

	if !ok {
		return fmt.Errorf("failed to find version %v as key in manifest", pinnedBundleVersion)
	}
	if !isEngineCompatible(currentEngineVersion, minEngineVersionForBundle) {
		return fmt.Errorf("policy-engine version %v is not compatible with min required policy-engine version %v in bundle version %v", currentEngineVersion, minEngineVersionForBundle, pinnedBundleVersion)
	}

	hash := sha256.New()

	if err := c.download(io.MultiWriter(w, hash), versionMap.Url); err != nil {
		return fmt.Errorf("download bundle: %v", err)
	}

	if checksum := hex.EncodeToString(hash.Sum(nil)); versionMap.Checksum != checksum {
		return fmt.Errorf("invalid checksum: expected %v, got %v", versionMap.Checksum, checksum)
	}
	return nil
}

func (c *Client) downloadJSON(url string, v any) error {
	var data bytes.Buffer

	if err := c.download(&data, url); err != nil {
		return fmt.Errorf("download: %v", err)
	}

	if err := json.NewDecoder(&data).Decode(v); err != nil {
		return fmt.Errorf("decode: %v", err)
	}

	return nil
}

func (c *Client) download(w io.Writer, url string) (e error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("create request: %v", err)
	}

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("perform request: %v", err)
	}

	defer func() {
		if err := res.Body.Close(); err != nil && e == nil {
			e = fmt.Errorf("close response body: %v", err)
		}
	}()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("invalid status code: %v", res.StatusCode)
	}

	if _, err := io.Copy(w, res.Body); err != nil {
		return fmt.Errorf("copy: %v", err)
	}

	return nil
}
