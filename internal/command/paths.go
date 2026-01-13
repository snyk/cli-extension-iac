package command

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	gitignore "github.com/sabhiram/go-gitignore"
	utils "github.com/snyk/go-application-framework/pkg/utils"
)

func normalizePaths(paths []string) ([]string, error) {
	var normalized []string

	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("read current working directory: %v", err)
	}

	for _, path := range paths {
		abs, err := filepath.Abs(path)
		if err != nil {
			return nil, fmt.Errorf("get absolute path: %v", err)
		}

		rel, err := filepath.Rel(cwd, abs)
		if err != nil {
			return nil, fmt.Errorf("get relative path: %v", err)
		}

		normalized = append(normalized, rel)
	}

	return normalized, nil
}

// applyExclusions expands directories to files and filters out excluded items using the
// go-application-framework FileFilter plus user-provided exclude patterns.
func (c Command) applyExclusions(paths []string) ([]string, error) {
	// If no excludes specified, return original paths
	if len(c.Exclude) == 0 {
		return paths, nil
	}

	// Build a combined list of files from each path, then filter by globs
	var result []string
	userExcludeRules, err := buildExclusionGlobs(strings.Join(c.Exclude, ","))
	if err != nil {
		return []string{}, err
	}

	for _, p := range paths {
		abs := p
		// normalize to absolute based on OS working dir for file filter
		if !filepath.IsAbs(p) {
			if a, err := filepath.Abs(p); err == nil {
				abs = a
			}
		}

		filter := utils.NewFileFilter(abs, c.Logger)
		info, err := c.FS.Stat(abs)
		if err != nil {
			return nil, err
		}
		if info.IsDir() {
			files := filter.GetAllFiles()
			filtered := filter.GetFilteredFiles(files, userExcludeRules)
			for f := range filtered {
				// keep as relative to cwd as expected by engine.normalizePaths step already done
				// here f is absolute; convert to relative to current working directory
				cwd, _ := os.Getwd()
				if rel, err := filepath.Rel(cwd, f); err == nil {
					result = append(result, rel)
				} else {
					result = append(result, f)
				}
			}
		} else {
			// Single file: check if excluded using matcher
			matcher := gitignore.CompileIgnoreLines(userExcludeRules...)
			if !matcher.MatchesPath(filepath.ToSlash(abs)) {
				cwd, _ := os.Getwd()
				if rel, err := filepath.Rel(cwd, abs); err == nil {
					result = append(result, rel)
				} else {
					result = append(result, abs)
				}
			}
		}
	}

	// De-duplicate
	seen := map[string]struct{}{}
	dedup := make([]string, 0, len(result))
	for _, r := range result {
		if _, ok := seen[r]; !ok {
			seen[r] = struct{}{}
			dedup = append(dedup, r)
		}
	}
	return dedup, nil
}

// BuildExclusionGlobs converts a comma-separated string into global glob patterns.
// It enforces basename matching (matching the name anywhere in the tree)
// rather than path-based matching, ensuring consistency with snyk test.
func buildExclusionGlobs(rawExcludeFlag string) ([]string, error) {
	if rawExcludeFlag == "" {
		return []string{}, nil
	}

	rawEntries := strings.Split(rawExcludeFlag, ",")
	// Pre-allocate space for the double-glob patterns
	patterns := make([]string, 0, len(rawEntries)*2)

	for _, entry := range rawEntries {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			continue
		}

		// Strictly forbid paths. This ensures we are doing basename matching.
		if strings.ContainsAny(trimmed, "/\\") {
			return nil, ErrPathNotAllowed
		}

		// Create global patterns to match the basename at any depth.
		// Using **/ ensures 'dir1' matches './dir1' and './src/dir1'.
		patterns = append(patterns, "**/"+trimmed)
		patterns = append(patterns, "**/"+trimmed+"/**")
	}

	return patterns, nil
}
