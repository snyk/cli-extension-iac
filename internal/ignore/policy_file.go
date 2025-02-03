package ignore

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// NewMatcherFromPolicy creates a new matcher based on the content of a .snyk
// policy file. If an error occurs while parsing the contents of the file or one
// of the rules within it, an error is returned. If the file is empty or doesn't
// contain any rules, a non-nil, empty matcher is still returned.
func NewMatcherFromPolicy(config []byte) (*Matcher, error) {
	var policy struct {
		Ignore map[string][]map[string]struct {
			Expires time.Time
		}
	}

	if err := yaml.Unmarshal(config, &policy); err != nil {
		return nil, fmt.Errorf("unmarshal policy: %v", err)
	}

	var matcher Matcher

	for policyID, policyRules := range policy.Ignore {
		for _, p := range policyRules {
			for pattern, ruleMeta := range p {
				if err := matcher.AddIgnore(policyID, ruleMeta.Expires, pattern); err != nil {
					return nil, fmt.Errorf("add policy rule: %v", err)
				}
			}
		}
	}

	return &matcher, nil
}
