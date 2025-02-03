package ignore

import (
	"fmt"
	"time"
)

// Matcher collects ignore rules and matches them to a vulnerability ID, an
// evaluation time and a path.
type Matcher struct {
	matchers map[string]vulnerabilityMatcher
}

// AddIgnore adds a new ignore to the matcher. It returns an error if the
// vulnerability ID or the pattern is invalid.
func (m *Matcher) AddIgnore(id string, expires time.Time, pattern string) error {
	if len(id) == 0 {
		return fmt.Errorf("empty vulnerability ID")
	}

	var matcher vulnerabilityMatcher

	if m.matchers != nil {
		matcher = m.matchers[id]
	}

	if err := matcher.addIgnore(expires, pattern); err != nil {
		return err
	}

	if m.matchers == nil {
		m.matchers = make(map[string]vulnerabilityMatcher)
	}

	m.matchers[id] = matcher

	return nil
}

// Match matches the ignores stored in this Matcher to the provided
// vulnerability ID, current evaluation time and path. The path is expressed as
// a slice of path components. Match returns true if at least one of the ignores
// in this Matcher matches the provided argument, false otherwise.
func (m *Matcher) Match(id string, now time.Time, parts ...string) bool {
	if m.matchers == nil {
		return false
	}

	if matcher, ok := m.matchers[id]; ok {
		return matcher.match(now, parts...)
	}

	return false
}
