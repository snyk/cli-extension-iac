package processor

import (
	"path/filepath"
	"strings"
	"time"

	"github.com/snyk/cli-extension-iac/internal/results"
)

type matcher interface {
	Match(id string, now time.Time, parts ...string) bool
}

func filterVulnerabilitiesByIgnores(r *results.Results, matcher matcher, now time.Time) *results.Results {
	if r == nil {
		return nil
	}

	var (
		kept    []results.Vulnerability
		ignored []results.Vulnerability
	)

	for _, v := range r.Vulnerabilities {
		var parts []string

		if file := v.Resource.File; len(file) > 0 {
			parts = append(parts, filepath.ToSlash(file))
		}

		if path := v.Resource.FormattedPath; len(path) > 0 {
			parts = append(parts, strings.Split(path, ".")...)
		}

		if matcher.Match(v.Rule.ID, now, parts...) {
			ignored = append(ignored, v)
		} else {
			kept = append(kept, v)
		}
	}

	result := *r

	result.Vulnerabilities = kept
	result.Metadata.IgnoredCount = len(ignored)

	return &result
}
