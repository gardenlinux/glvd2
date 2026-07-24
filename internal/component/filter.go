package component

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// FilterConfig contains the different filter rules for a component list like the vendor-product pair list
// or a package URL list.
type FilterConfig struct {
	Rules []Rule `toml:"rules"`
}

// Rule defines a single filter rule that applies to one or more groups.
type Rule struct {
	// Groups list for which grouping values like vendor for CPEs or namespace for PURLs this rule should be applied.
	// The special value "*" means the rule applies to any group.
	Groups []string `toml:"groups"`

	// DiscardAll discards all entries for the matched group.
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

// Filter evaluates component identifier lists against loaded filter rules.
type Filter struct {
	// groupRules maps a group name to the rules that apply to it.
	groupRules map[string][]Rule
	// wildcardRules apply to any group.
	wildcardRules []Rule
}

// TODO: use this SafePath pattern everywhere

type SafePath string

const (
	DefaultPackageIDFilterConfigPath     SafePath = "./config/package_id_filter.toml"
	DefaultCPEFilterConfigPath           SafePath = "./config/cpe_filter.toml"
	DefaultVendorProductFilterConfigPath SafePath = "./config/vendor_product_filter.toml"
)

// LoadFilterConfig reads and parses a TOML filter configuration file from the given path.
func loadFilterConfig(path SafePath) (FilterConfig, error) {
	data, err := os.ReadFile(string(path))
	if err != nil {
		return FilterConfig{}, fmt.Errorf("reading filter config %q: %w", path, err)
	}

	var cfg FilterConfig
	if err = toml.Unmarshal(data, &cfg); err != nil {
		return FilterConfig{}, fmt.Errorf("parsing filter config %q: %w", path, err)
	}

	return cfg, nil
}

// NewFilter creates a new vendor-product pair filter from the given configuration TOML-file.
func NewFilter(path SafePath) (Filter, error) {
	cfg, err := loadFilterConfig(path)
	if err != nil {
		return Filter{}, err
	}

	f, _ := NewFilterFromRules(cfg.Rules)

	return f, nil
}

// NewFilterFromRules creates a Filter directly from a slice of rules (useful for testing).
func NewFilterFromRules(rules []Rule) (Filter, error) {
	f := Filter{
		groupRules: make(map[string][]Rule),
	}

	for _, rule := range rules {
		for _, group := range rule.Groups {
			if group == "*" {
				f.wildcardRules = append(f.wildcardRules, rule)
			} else {
				f.groupRules[group] = append(f.groupRules[group], rule)
			}
		}
	}

	return f, nil
}

// ShouldDiscard returns true if the given group,name-pair should be filtered out,
// according to the loaded filter list.
func (f *Filter) ShouldDiscard(group, name string) bool {
	if rules, ok := f.groupRules[group]; ok {
		for i := range rules {
			if matchRule(rules[i], name) {
				return true
			}
		}
	}

	for i := range f.wildcardRules {
		if matchRule(f.wildcardRules[i], name) {
			return true
		}
	}

	return false
}

// matchRule checks whether a name matches a single rule.
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
