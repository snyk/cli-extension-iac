package processor

import (
	"fmt"
	"path/filepath"
	"regexp"

	"github.com/snyk/cli-extension-iac/internal/git"
)

func (p *ResultsProcessor) readWorkingDirectoryName() (string, error) {
	cwd, err := p.GetWd()
	if err != nil {
		return "", err
	}

	return filepath.Base(cwd), nil
}

func (p *ResultsProcessor) readRemoteURL() (string, error) {
	if p.RemoteRepoUrl != "" {
		return p.RemoteRepoUrl, nil
	}

	cwd, err := p.GetWd()
	if err != nil {
		return "", err
	}

	repoRootDir, err := p.GetRepoRootDir(cwd)
	if err != nil {
		return "", err
	}

	if cwd != repoRootDir {
		return "", nil
	}

	gitOriginUrl, err := p.GetOriginUrl(cwd)
	if err != nil {
		return "", err
	}

	return gitOriginUrl, nil
}

func (p *ResultsProcessor) computeProjectURL() (string, error) {
	remoteURL, err := p.readRemoteURL()
	if err != nil {
		p.Logger.Warn().Err(err).Msg("read remote URL")
		return p.readWorkingDirectoryName()
	}
	if remoteURL == "" {
		return p.readWorkingDirectoryName()
	}

	return remoteURL, nil
}

func (p *ResultsProcessor) computeProjectName() (string, error) {
	if p.TargetName != "" {
		return p.TargetName, nil
	}

	remoteURL, err := p.readRemoteURL()
	if err != nil {
		p.Logger.Warn().Err(err).Msg("read remote URL")
		return p.readWorkingDirectoryName()
	}
	if remoteURL == "" {
		return p.readWorkingDirectoryName()
	}

	projectName, err := getProjectNameFromGitOriginUrl(remoteURL)
	if err != nil {
		p.Logger.Warn().Err(err).Msg("compute project name from remote URL")
		return p.readWorkingDirectoryName()
	}
	if projectName == "" {
		return p.readWorkingDirectoryName()
	}

	return projectName, nil
}

var (
	githubPathRegexp      = regexp.MustCompile(`/?(.*).git/?`)
	azureDevOpsPathRegexp = regexp.MustCompile(`^/([^/]+)/([^/]+)/_git/([^/]+)$`)
)

func getProjectNameFromGitOriginUrl(url string) (string, error) {
	gitURL := git.ParseUrl(url)
	if match := azureDevOpsPathRegexp.FindStringSubmatch(gitURL.Path); match != nil {
		return fmt.Sprintf("%s/%s/%s", match[1], match[2], match[3]), nil
	}

	if match := githubPathRegexp.FindStringSubmatch(gitURL.Path); match != nil {
		return match[1], nil
	}

	return "", nil
}
