// Package flavorinventory builds the per-release, per-flavor source membership artifact:
// release -> flavor -> set of source identity PURLs.
// It is a sibling of the identity inventory (internal/gardenlinux/inventory), differing only in that
// it keeps the per-release, per-flavor breakdown instead of unioning everything.
package flavorinventory

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/packages"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/sbom"
	"github.com/gardenlinux/glvd2/internal/purl"
)

// Inventory is the per-release, per-flavor source membership artifact. The release key is
// the GL version string ("1877.26", "2150.12.0"). The zero value is not usable; construct
// it via an Accumulator.
type Inventory struct {
	// byRelease maps: a release key -> flavor -> set of source identity PURLs.
	byRelease map[string]map[string]purl.VariantMap[struct{}]
}

// Record is the serialized shape written to the audit artifact.
type Record struct {
	Releases []ReleaseEntry `json:"releases"`
}

// ReleaseEntry is one release row, mapping each flavor to its sorted source identity PURLs.
type ReleaseEntry struct {
	Release string              `json:"release"`
	Flavors map[string][]string `json:"flavors"`
}

// Record returns the serialized flavor inventory. Releases are ordered numerically and
// sources lexically; flavors serialize as a JSON object with keys sorted by the encoder, so
// identical input yields identical bytes regardless of arrival order.
func (i Inventory) Record() Record {
	rec := Record{}

	releases := slices.SortedFunc(maps.Keys(i.byRelease), compareReleases)
	rec.Releases = make([]ReleaseEntry, 0, len(releases))
	for _, rel := range releases {
		entry := ReleaseEntry{Release: rel, Flavors: make(map[string][]string)}
		for flavor, sources := range i.byRelease[rel] {
			entry.Flavors[flavor] = slices.Sorted(maps.Keys(sources))
		}
		rec.Releases = append(rec.Releases, entry)
	}

	return rec
}

// HasFlavors reports whether the release has usable flavor membership.
func (i Inventory) HasFlavors(release string) bool {
	_, ok := i.byRelease[release]

	return ok
}

// Releases returns the covered release versions, ordered numerically.
func (i Inventory) Releases() []string {
	return slices.SortedFunc(maps.Keys(i.byRelease), compareReleases)
}

// Flavors returns the covered flavor names for a release, sorted.
// It returns nil for a release without usable flavor membership.
func (i Inventory) Flavors(release string) []string {
	flavors, ok := i.byRelease[release]
	if !ok {
		return nil
	}

	return slices.Sorted(maps.Keys(flavors))
}

// Contains reports whether identityPURL is a member of the release flavor, using namespace-tolerant matching.
// A release or flavor that is not covered contains nothing.
func (i Inventory) Contains(release, flavor, identityPURL string) (bool, error) {
	sources, ok := i.flavorSourcePURLs(release, flavor)
	if !ok {
		return false, nil
	}

	_, found, err := sources.Get(identityPURL)
	if err != nil {
		return false, fmt.Errorf("membership lookup for %q: %w", identityPURL, err)
	}

	return found, nil
}

// flavorSourcePURLs returns the source PURL set of a release flavor and whether it is covered.
func (i Inventory) flavorSourcePURLs(release, flavor string) (purl.VariantMap[struct{}], bool) {
	flavors, ok := i.byRelease[release]
	if !ok {
		return nil, false
	}
	sources, ok := flavors[flavor]

	return sources, ok
}

// compareReleases orders release version strings numerically. Strings that are neither
// major.minor nor major.minor.patch are unparseable and sort after parseable ones,
// lexically among themselves, so the ordering is total and deterministic.
func compareReleases(a, b string) int {
	fa, okA := releaseFields(a)
	fb, okB := releaseFields(b)
	switch {
	case !okA && !okB:
		return strings.Compare(a, b)
	case !okA:
		return 1
	case !okB:
		return -1
	default:
		return slices.Compare(fa, fb)
	}
}

// releaseRegex matches a major.minor or major.minor.patch version string.
var releaseRegex = regexp.MustCompile(`^(?P<major>\d+)\.(?P<minor>\d+)(?:\.(?P<patch>\d+))?$`)

// releaseFields parses a major.minor or major.minor.patch version string and returns its numeric components.
// Returns false when s does not match either form.
func releaseFields(s string) ([]int, bool) {
	m := releaseRegex.FindStringSubmatch(s)
	if m == nil {
		return nil, false
	}
	fields := make([]int, 0, len(m)-1)
	for _, g := range m[1:] {
		if g == "" {
			break
		}

		n, err := strconv.Atoi(g) // always succeeds: group contains only digits
		if err != nil {
			return []int{}, false
		}

		fields = append(fields, n)
	}

	return fields, true
}

// Accumulator accumulates the per-release, per-flavor membership across the shared SBOM pass.
// It implements [sbom.Consumer]. The zero value is not usable; construct it via [NewAccumulator].
type Accumulator struct {
	byRelease map[string]map[string]purl.VariantMap[struct{}]
}

var _ sbom.Consumer = (*Accumulator)(nil)

// NewAccumulator constructs a per-release, per-flavor membership accumulator.
func NewAccumulator() *Accumulator {
	return &Accumulator{byRelease: make(map[string]map[string]purl.VariantMap[struct{}])}
}

// AddSBOM folds one release-flavor SBOM's sources into that flavor's membership set.
// A conversion error is a hard failure.
func (a *Accumulator) AddSBOM(releaseVersion, flavor string, bom *cdx.BOM) error {
	pkgs, err := packages.PackageListFromSBOM(bom)
	if err != nil {
		return fmt.Errorf("converting SBOM: %w", err)
	}

	return a.addPackages(releaseVersion, flavor, pkgs)
}

// MissingSBOMSet records that the release lacks a complete SBOM set, so no flavor membership
// is known for it. The release is left absent from the inventory. The release-wide InRelease
// fallback that keeps release-level analysis working lives in the identity inventory.
func (a *Accumulator) MissingSBOMSet(_ context.Context, releaseVersion string) error {
	slog.Warn("not all flavors of the release have an SBOM; "+
		"recording no flavor membership for the release",
		slog.String("release", releaseVersion))

	return nil
}

// Result returns the assembled inventory.
func (a *Accumulator) Result() Inventory {
	slog.Info("built GL per-release per-flavor source inventory",
		slog.Int("releasesWithFlavorMembership", len(a.byRelease)))

	return Inventory{byRelease: a.byRelease}
}

// addPackages folds each package's source into the (release, flavor) membership set.
func (a *Accumulator) addPackages(releaseVersion, flavor string, pkgs []packages.Package) error {
	flavors, ok := a.byRelease[releaseVersion]
	if !ok {
		flavors = make(map[string]purl.VariantMap[struct{}])
		a.byRelease[releaseVersion] = flavors
	}
	sources, ok := flavors[flavor]
	if !ok {
		sources = make(purl.VariantMap[struct{}])
		flavors[flavor] = sources
	}

	for _, pkg := range pkgs {
		identity, err := pkg.IdentityPURL()
		if err != nil {
			return fmt.Errorf("identity PURL for source %q: %w", pkg.Source, err)
		}

		sources[identity] = struct{}{}
	}

	return nil
}
