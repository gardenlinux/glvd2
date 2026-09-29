// Package vendormap contains the vendored-dependency inclusion resolver.
//
// It is the auto-generated counterpart to the curated glmap:
// from the SBOM dependency graph it maps a vendored (non-deb)
// component's own CVE identifiers (PURL, CPE) to the parent deb-source PURL
// that ships it, unioned across all currently maintained releases.
package vendormap

import (
	"context"
	"fmt"
	"log/slog"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/gardenlinux/glvd2/internal/cpe"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/glrd"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/packages"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/sbom"
	"github.com/gardenlinux/glvd2/internal/glmap"
	"github.com/gardenlinux/glvd2/internal/identifier"
	"github.com/gardenlinux/glvd2/internal/purl"
)

// Accumulator accumulates the derived vendored-inclusion rules across the shared
// SBOM pass. It implements [sbom.Consumer]. Construct it via [NewAccumulator].
type Accumulator struct {
	derived []glmap.Rule
}

var _ sbom.Consumer = (*Accumulator)(nil)

// NewAccumulator constructs a vendored-inclusion accumulator.
func NewAccumulator() *Accumulator {
	return &Accumulator{}
}

// AddSBOM folds a release-flavor SBOM's vendored-inclusion rules into the union.
// Each vendored group (one deb source and the components it ships) becomes a
// single rule mapping the shipped components' identifiers to the deb-source identity PURL.
// A derivation error is a hard failure.
func (a *Accumulator) AddSBOM(bom *cdx.BOM) error {
	groups, err := packages.VendoredFromSBOM(bom)
	if err != nil {
		return fmt.Errorf("deriving vendored components: %w", err)
	}

	for _, group := range groups {
		rule, ruleErr := vendoredRule(group)
		if ruleErr != nil {
			return fmt.Errorf("building vendored rule: %w", ruleErr)
		}

		if !rule.IsEmpty() {
			a.derived = append(a.derived, rule)
		}
	}

	return nil
}

func vendoredRule(group packages.ShippedBy) (glmap.Rule, error) {
	target, err := group.Target.IdentityPURL()
	if err != nil {
		return glmap.Rule{}, fmt.Errorf("deriving target identity PURL: %w", err)
	}

	rule := glmap.Rule{TargetPURL: target}
	for _, child := range group.Children {
		if child.PURL != "" {
			if canon, canonErr := purl.Canonicalize(child.PURL); canonErr == nil {
				rule.InputPURLs = append(rule.InputPURLs, canon)
			}
		}

		if child.CPE != "" {
			if wfn, parseErr := cpe.Parse(child.CPE); parseErr == nil {
				if vendor, product, ok := wfn.VendorProduct(); ok {
					rule.CPEs = append(rule.CPEs, identifier.VendorProduct{Vendor: vendor, Product: product})
				}
			}
		}
	}

	return rule, nil
}

// MissingSBOMSet can be ignored here:
// without an SBOM there is no dependency graph to derive vendored inclusion from.
func (a *Accumulator) MissingSBOMSet(_ context.Context, release glrd.Release) error {
	slog.Debug("release has no complete SBOM set; no vendored rules derived",
		slog.String("release", release.Name))

	return nil
}

// Result compiles the accumulated rules into the derived resolver.
//
// glmap is set-valued, so unioning across releases and packages just works:
// duplicate (identifier, target) pairs dedupe and multiple targets accumulate.
func (a *Accumulator) Result() (glmap.Rules, error) {
	rules, err := glmap.NewFromRules(a.derived)
	if err != nil {
		return glmap.Rules{}, fmt.Errorf("compiling derived vendored inclusion rules: %w", err)
	}

	slog.Info("built derived vendored-dependency inclusion", slog.Int("rules", len(a.derived)))

	return rules, nil
}
