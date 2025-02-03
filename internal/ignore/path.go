package ignore

import (
	"fmt"
	"strings"
)

type pathMatcher struct {
	parts []string
}

func (m *pathMatcher) setPattern(pattern string) error {
	if len(pattern) == 0 {
		return fmt.Errorf("empty pattern")
	}

	parts := strings.Split(pattern, " > ")

	for i, part := range parts {
		parts[i] = strings.TrimSpace(part)
	}

	m.parts = parts

	return nil
}

func (m *pathMatcher) match(parts ...string) bool {
	for i, part := range m.parts {
		if i >= len(parts) {
			return false
		}

		if part == "*" {
			if i == len(m.parts)-1 {
				return true
			}
			continue
		}

		if part != parts[i] {
			return false
		}
	}

	return len(parts) == len(m.parts)
}
