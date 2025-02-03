package command

import (
	"fmt"
	"os"
	"path/filepath"
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
