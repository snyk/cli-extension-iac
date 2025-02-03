//go:build !windows

package engine

import (
	"path/filepath"
	"strings"
)

func isHidden(path string) (bool, error) {
	return isHiddenFileName(filepath.Base(path)), nil
}

func isHiddenFileName(name string) bool {
	return name != "." && strings.HasPrefix(name, ".")
}
