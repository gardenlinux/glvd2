// Package glmap provides the Garden Linux specific inclusion mapping.
//
// It maps CVE component identifiers to a single Garden Linux target PURL that
// we deliberately care about. It is the counterpart to the debmap matcher's
// noise filter: instead of deciding whether a CVE's identifier should be
// discarded, it decides whether a CVE's identifier resolves to a Garden Linux
// PURL.
//
// The mapping operates on the normalized CVE identifiers (vendor-product pairs,
// CPE vendor/product, package IDs, and PURLs) and maps any of them to one or
// more target GL PURLs. Each rule is a curated "we care about this" assertion,
// either for a GL-only package Debian never knew about, or to override a Debian
// NOT-FOR-US decision where GL ships the affected software.
package glmap

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/gardenlinux/glvd2/internal/configpath"
	"github.com/gardenlinux/glvd2/internal/identifier"
	"github.com/gardenlinux/glvd2/internal/ingestion/cvelistv5"
	"github.com/gardenlinux/glvd2/internal/purl"
	"github.com/pelletier/go-toml/v2"
)

// Rules is the compiled, exact-match lookup set.
// The zero value is not usable; construct via New or NewFromRules.
type Rules struct {
	m map[string]map[string]struct{} // prefixed identifier key -> set of target GL PURLs
}

// keySep separates key components in our [Rules] keys.
// NUL cannot appear in these identifier values, so it unambiguously delimits.
const keySep = "\x00"

func purlKey(canonPURL string) string { return "purl" + keySep + canonPURL }

func vpKey(vendor, product string) string {
	return "vp" + keySep + strings.ToLower(vendor) + keySep + strings.ToLower(product)
}

func cpeKey(vendor, product string) string {
	return "cpe" + keySep + strings.ToLower(vendor) + keySep + strings.ToLower(product)
}

func pidKey(collectionURL, packageName string) string {
	return "pid" + keySep + strings.ToLower(collectionURL) + keySep + strings.ToLower(packageName)
}

// PackageID is a collection-URL and package-name pair used in rule configuration.
type PackageID struct {
	CollectionURL string `toml:"collection_url"`
	PackageName   string `toml:"package_name"`
}

// Rule maps a set of input identifiers to a single target GL PURL.
type Rule struct {
	TargetPURL     string                     `toml:"target_purl"`
	InputPURLs     []string                   `toml:"input_purls,omitempty"`
	CPEs           []identifier.VendorProduct `toml:"cpes,omitempty"`
	VendorProducts []identifier.VendorProduct `toml:"vendor_products,omitempty"`
	PackageIDs     []PackageID                `toml:"package_ids,omitempty"`
}

// IsEmpty reports whether the rule carries no input identifiers.
func (r Rule) IsEmpty() bool {
	return len(r.InputPURLs) == 0 &&
		len(r.CPEs) == 0 &&
		len(r.VendorProducts) == 0 &&
		len(r.PackageIDs) == 0
}

// config is the raw TOML structure.
type config struct {
	Rules []Rule `toml:"rules"`
}

// New loads and validates the TOML config at path.
// It returns an error if the file cannot be read, parsed, or fails validation.
func New(path configpath.SafePath) (*Rules, error) {
	const errMsg = "reading GL-specific inclusion config %q: %w"

	data, err := os.ReadFile(string(path))
	if err != nil {
		return nil, fmt.Errorf(errMsg, path, err)
	}

	var cfg config
	if err = toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf(errMsg, path, err)
	}

	rules, err := NewFromRules(cfg.Rules)
	if err != nil {
		return nil, fmt.Errorf(errMsg, path, err)
	}

	return rules, nil
}

// NewFromRules builds a [Rules] directly from a slice of rules.
// Useful for testing without a config file on disk.
func NewFromRules(rules []Rule) (*Rules, error) {
	r := &Rules{m: make(map[string]map[string]struct{})}

	for i := range rules {
		if err := r.addRule(rules[i]); err != nil {
			return nil, err
		}
	}

	return r, nil
}

// addRule validates a single rule and inserts all of its input identifier keys.
func (r *Rules) addRule(rule Rule) error {
	if rule.TargetPURL == "" {
		return errors.New("rule has empty target_purl")
	}

	target, err := purl.Canonicalize(rule.TargetPURL)
	if err != nil {
		return fmt.Errorf("invalid target_purl %q: %w", rule.TargetPURL, err)
	}

	keys, err := ruleKeys(rule)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return fmt.Errorf("rule for target_purl %q has no input identifiers", rule.TargetPURL)
	}

	for _, key := range keys {
		targets, ok := r.m[key]
		if !ok {
			targets = make(map[string]struct{})
			r.m[key] = targets
		}
		targets[target] = struct{}{}
	}

	return nil
}

// ruleKeys builds the lookup keys for all input identifiers of a rule.
func ruleKeys(rule Rule) ([]string, error) {
	var keys []string

	for _, vp := range rule.VendorProducts {
		keys = append(keys, vpKey(vp.Vendor, vp.Product))
	}
	for _, cpe := range rule.CPEs {
		keys = append(keys, cpeKey(cpe.Vendor, cpe.Product))
	}
	for _, pid := range rule.PackageIDs {
		keys = append(keys, pidKey(pid.CollectionURL, pid.PackageName))
	}
	for _, p := range rule.InputPURLs {
		canon, err := purl.Canonicalize(p)
		if err != nil {
			return nil, fmt.Errorf("invalid input_purl %q: %w", p, err)
		}
		keys = append(keys, purlKey(canon))
	}

	return keys, nil
}

// Lookup returns the sorted, deduplicated set of target GL PURLs matched by any
// of the CVE's identifiers, across all identifier types. It returns nil if none
// match. A single identifier may contribute several targets, and several
// identifiers may contribute the same target; both are collapsed into one set.
func (r *Rules) Lookup(ids cvelistv5.Identifiers) []string {
	matched := make(map[string]struct{})

	for _, vp := range ids.VendorProductPairs {
		collect(matched, r.m[vpKey(vp.Vendor, vp.Product)])
	}
	for _, wfn := range ids.WFNs {
		vendor, product, ok := wfn.VendorProduct()
		if !ok {
			continue
		}
		collect(matched, r.m[cpeKey(vendor, product)])
	}
	for _, pid := range ids.PackageIDs {
		collect(matched, r.m[pidKey(pid.CollectionURL, pid.PackageName)])
	}
	for _, p := range ids.PackageURLs {
		canon, err := purl.Canonicalize(p)
		if err != nil {
			continue
		}
		collect(matched, r.m[purlKey(canon)])
	}

	if len(matched) == 0 {
		return nil
	}

	out := make([]string, 0, len(matched))
	for t := range matched {
		out = append(out, t)
	}
	slices.Sort(out)

	return out
}

// collect adds every target in src to dst.
func collect(dst, src map[string]struct{}) {
	for t := range src {
		dst[t] = struct{}{}
	}
}
