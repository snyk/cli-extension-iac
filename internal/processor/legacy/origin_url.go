package legacy

import (
	"fmt"
	"strings"

	"github.com/snyk/cli-extension-iac/internal/git"
)

// The function below is based on:
// https://github.com/snyk/cli/blob/master/src/lib/project-metadata/target-builders/git.ts#L22-L47
func formatOriginUrl(originUrl string) (string, error) {
	if originUrl == "" {
		return "", nil
	}

	parsedUrl := git.ParseUrl(originUrl)
	if parsedUrl.Host != "" && parsedUrl.Scheme != "" && isAllowedScheme(parsedUrl.Scheme) {
		return fmt.Sprintf("%s://%s/%s", "http", strings.Trim(parsedUrl.Host, "/"), strings.Trim(parsedUrl.Path, "/")), nil
	}

	return parsedUrl.String(), nil
}

func isAllowedScheme(scheme string) bool {
	for _, allowed := range []string{"ssh", "http", "https", "ftp", "ftps"} {
		if allowed == scheme {
			return true
		}
	}
	return false
}
