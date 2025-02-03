package git

import (
	"fmt"
	"net/url"
	"regexp"

	goGit "github.com/go-git/go-git/v5"
)

func GetRepoRootDir(path string) (string, error) {
	repo, err := goGit.PlainOpenWithOptions(path, &goGit.PlainOpenOptions{
		DetectDotGit: true,
	})
	if err != nil {
		return "", err
	}

	worktree, err := repo.Worktree()
	if err != nil {
		return "", err
	}

	return worktree.Filesystem.Root(), nil
}

func GetOriginUrl(path string) (string, error) {
	repo, err := goGit.PlainOpenWithOptions(path, &goGit.PlainOpenOptions{
		DetectDotGit: true,
	})
	if err != nil {
		return "", err
	}

	repoConfig, err := repo.Config()
	if err != nil {
		return "", err
	}

	if origin := repoConfig.Remotes["origin"]; origin != nil {
		return sanitizeUrl(origin.URLs[0]), nil
	}

	return "", nil
}

var originRegexp = regexp.MustCompile(`^(.+@)?(.+):(.+)$`)

func sanitizeUrl(raw string) string {
	if u, err := url.Parse(raw); err == nil && (u.Scheme == "http" || u.Scheme == "https" || u.Scheme == "ssh") {
		return fmt.Sprintf("https://%s%s", u.Host, u.Path)
	}

	if match := originRegexp.FindStringSubmatch(raw); match != nil && len(match[2]) > 0 && len(match[3]) > 0 {
		return fmt.Sprintf("https://%s/%s", match[2], match[3])
	}

	return raw
}
