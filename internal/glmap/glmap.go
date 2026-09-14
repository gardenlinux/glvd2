// Package glmap provides the Garden Linux specific inclusion mapping.
//
// It maps CVE component identifiers to a single Garden Linux target PURL that
// we deliberately care about. It is the counterpart to the debmap matcher's
// noise filter: instead of deciding whether a CVE's identifier should be
// discarded, it decides whether a CVE's identifier resolves to a Garden Linux
// PURL.
//
// The mapping operates on the normalized CVE identifiers (vendor-product pairs,
// CPE vendor/product, package IDs, and PURLs) and maps any of them to a single
// target GL PURL. Each rule is a curated "we care about this" assertion, either
// for a GL-only package Debian never knew about, or to override a Debian
// NOT-FOR-US decision where GL ships the affected software.
//
// The identifier sets across all rules must be disjoint. This is validated at
// load time, so a successful load proves that any identifier resolves to at most
// one target PURL.
package glmap

import (
	"errors"
	"fmt"
	"os"
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
	m map[string]string // prefixed identifier key -> target GL PURL
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

// readableKey renders a key for error messages by replacing the NUL separators.
func readableKey(key string) string {
	return strings.ReplaceAll(key, keySep, "|")
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
	r := &Rules{m: make(map[string]string)}

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
		if existing, ok := r.m[key]; ok {
			return fmt.Errorf(
				"identifier %q maps to both %q and %q: identifier sets must be disjoint",
				readableKey(key), existing, target,
			)
		}
		r.m[key] = target
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

// Lookup returns the target GL PURL for the first matching identifier, or "" if none match.
// Because the identifier sets are disjoint: any match is a unique match.
func (r *Rules) Lookup(ids cvelistv5.Identifiers) string {
	for _, vp := range ids.VendorProductPairs {
		if t, ok := r.m[vpKey(vp.Vendor, vp.Product)]; ok {
			return t
		}
	}
	for _, wfn := range ids.WFNs {
		vendor, product, ok := wfn.VendorProduct()
		if !ok {
			continue
		}
		if t, found := r.m[cpeKey(vendor, product)]; found {
			return t
		}
	}
	for _, pid := range ids.PackageIDs {
		if t, ok := r.m[pidKey(pid.CollectionURL, pid.PackageName)]; ok {
			return t
		}
	}
	for _, p := range ids.PackageURLs {
		canon, err := purl.Canonicalize(p)
		if err != nil {
			continue
		}
		if t, ok := r.m[purlKey(canon)]; ok {
			return t
		}
	}

	return ""
}
