// Package filter provides the component noise filter used by the debmap matcher
// to discard irrelevant CVE identifiers before they are indexed.
//
// The engine groups rules by an identifier dimension (vendor for VP pairs,
// vendor for CPEs, collection URL for package IDs) and tests the second
// dimension (product / name) against prefix, suffix, contains and equals patterns.
// A wildcard group ("*") matches any first dimension.
package filter

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/gardenlinux/glvd2/internal/configpath"
	"github.com/pelletier/go-toml/v2"
)

// config is the raw TOML structure.
type config struct {
	Rules []Rule `toml:"rules"`
}

// Rule defines a single filter rule applied to one or more groups.
type Rule struct {
	// Groups lists the grouping values (e.g. vendor for VP pairs) to which this rule applies.
	// The special value "*" matches any group.
	Groups []string `toml:"groups"`

	// DiscardAll discards every entry for the matched group.
	DiscardAll bool `toml:"discard_all"`

	// PrefixFilters discards if the name starts with any of these strings.
	PrefixFilters []string `toml:"prefix_filters"`

	// ContainsFilters discards if the name contains any of these strings.
	ContainsFilters []string `toml:"contains_filters"`

	// SuffixFilters discards if the name ends with any of these strings.
	SuffixFilters []string `toml:"suffix_filters"`

	// Equals discards if the name exactly equals any of these strings.
	Equals []string `toml:"equals"`
}

// Rules is the compiled filter rule set.
// The zero value is not usable; construct via New or NewFromRules.
type Rules struct {
	// groupRules maps a group name to the rules that apply to it.
	groupRules map[string][]Rule
	// wildcardRules apply to any group.
	wildcardRules []Rule
}

// New loads and validates the TOML config at path, returning a compiled Rules.
func New(path configpath.SafePath) (Rules, error) {
	data, err := os.ReadFile(string(path))
	if err != nil {
		return Rules{}, fmt.Errorf("reading filter config %q: %w", path, err)
	}

	var cfg config
	if err = toml.Unmarshal(data, &cfg); err != nil {
		return Rules{}, fmt.Errorf("parsing filter config %q: %w", path, err)
	}

	return NewFromRules(cfg.Rules), nil
}

// NewFromRules builds a Rules directly from a slice of rules.
// Useful for testing without a config file on disk.
func NewFromRules(rules []Rule) Rules {
	r := Rules{groupRules: make(map[string][]Rule)}

	for _, rule := range rules {
		for _, group := range rule.Groups {
			if group == "*" {
				r.wildcardRules = append(r.wildcardRules, rule)
			} else {
				r.groupRules[group] = append(r.groupRules[group], rule)
			}
		}
	}

	return r
}

// ShouldDiscard reports whether the given (group, name) pair should be discarded
// according to the loaded rules.
func (r Rules) ShouldDiscard(group, name string) bool {
	if rules, ok := r.groupRules[group]; ok {
		for i := range rules {
			if matchRule(rules[i], name) {
				return true
			}
		}
	}

	for i := range r.wildcardRules {
		if matchRule(r.wildcardRules[i], name) {
			return true
		}
	}

	return false
}

// matchRule reports whether a name matches a single rule.
func matchRule(rule Rule, name string) bool {
	if rule.DiscardAll {
		return true
	}

	for _, p := range rule.PrefixFilters {
		if strings.HasPrefix(name, p) {
			return true
		}
	}

	for _, s := range rule.SuffixFilters {
		if strings.HasSuffix(name, s) {
			return true
		}
	}

	for _, c := range rule.ContainsFilters {
		if strings.Contains(name, c) {
			return true
		}
	}

	return slices.Contains(rule.Equals, name)
}
