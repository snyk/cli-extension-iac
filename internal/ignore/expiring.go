package ignore

import "time"

type expiringMatcher struct {
	expires time.Time
	matcher pathMatcher
}

func (m *expiringMatcher) setExpires(expires time.Time) {
	m.expires = expires
}

func (m *expiringMatcher) setPattern(pattern string) error {
	return m.matcher.setPattern(pattern)
}

func (m *expiringMatcher) match(now time.Time, parts ...string) bool {
	return (m.expires.IsZero() || now.Before(m.expires)) && m.matcher.match(parts...)
}
