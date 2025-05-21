package git

import (
	"net/url"
	"regexp"
	"strings"
)

var (
	// (user)?@host:path.git
	scpGithubUrlRegexp = regexp.MustCompile(`^(([\w._-]+)@)?([\w.-]+):(.*)$`)

	validTransportSchemas = map[string]bool{
		"ssh":     true,
		"git":     true,
		"git+ssh": true,
		"http":    true,
		"https":   true,
		"ftp":     true,
		"ftps":    true,
		"rsync":   true,
		"file":    true,
	}
)

func ParseUrl(urlStr string) *url.URL {
	// match standard URL & validate schema
	parsedUrl, err := url.Parse(urlStr)
	if err == nil && validTransportSchemas[parsedUrl.Scheme] {
		return parsedUrl
	}

	// match SCP URL e.g. user@host:path
	match := scpGithubUrlRegexp.FindStringSubmatch(urlStr)
	if match == nil {
		// no match for standard URL or SCP URL
		// return a local URL
		return &url.URL{
			Scheme: "file",
			Host:   "",
			Path:   urlStr,
		}
	}

	// if there's a match then we have the following data at indexes in match
	// 0: full string
	// 1: (\w+)@ match -> user
	// 2: (\w+) match  -> user
	// 3: ([\w.-]+) match -> host
	// 4: (.*) -> path, can include query param

	// get user info
	var user *url.Userinfo
	if match[2] != "" {
		user = url.User(match[2])
	}

	// get query params
	path, queryParams := match[4], ""
	if strings.Contains(match[4], "?") {
		strs := strings.Split(match[4], "?")
		path = strs[0]
		queryParams = strs[1]
	}

	// SCP URL with ssh scheme
	return &url.URL{
		Scheme:   "ssh",
		User:     user,
		Host:     match[3],
		Path:     path,
		RawQuery: queryParams,
	}
}
