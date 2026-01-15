package command

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog"
	gitignore "github.com/sabhiram/go-gitignore"
	utils "github.com/snyk/go-application-framework/pkg/utils"
	"github.com/spf13/afero"
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

// ApplyExclusions expands directories to files and filters out excluded items using the
// go-application-framework FileFilter plus user-provided exclude patterns.
func applyExclusions(exclude []string, fs afero.Fs, logger *zerolog.Logger, paths []string, cwd string) ([]string, error) {
	// If no excludes specified, return original paths
	if len(exclude) == 0 {
		return paths, nil
	}

	// Build a combined list of files from each path, then filter by globs
	userExcludeRules, err := buildExclusionGlobs(strings.Join(exclude, ","))
	if err != nil {
		return []string{}, err
	}
	excluder := gitignore.CompileIgnoreLines(userExcludeRules...)

	var result []string
	for _, p := range paths {
		// normalize to absolute based on OS working dir for file filter
		abs := resolveAbs(p)
		info, err := fs.Stat(abs)
		if err != nil {
			return nil, err
		}

		if info.IsDir() {
			filter := utils.NewFileFilter(abs, logger)
			files := filter.GetAllFiles()
			filtered := filter.GetFilteredFiles(files, userExcludeRules)
			for f := range filtered {
				// keep as relative to cwd as expected by engine.normalizePaths step already done
				// here f is absolute; convert to relative to current working directory
				result = append(result, makeRelative(f, cwd))
			}
			continue
		}

		// Handle file exclusion
		if !excluder.MatchesPath(filepath.ToSlash(abs)) {
			result = append(result, makeRelative(abs, cwd))
		}
	}
	return deduplicatePaths(result), nil
}

func makeRelative(path, cwd string) string {
	if rel, err := filepath.Rel(cwd, path); err == nil {
		return rel
	}
	return path
}

func resolveAbs(p string) string {
	if !filepath.IsAbs(p) {
		if a, err := filepath.Abs(p); err == nil {
			return a
		}
	}
	return p
}

func deduplicatePaths(paths []string) []string {
	seen := make(map[string]struct{}, len(paths))
	dedup := make([]string, 0, len(paths))
	for _, p := range paths {
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			dedup = append(dedup, p)
		}
	}
	return dedup
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
