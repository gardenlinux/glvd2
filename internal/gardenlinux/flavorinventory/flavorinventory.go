// Package flavorinventory builds the version-free, per-release per-flavor source inclusion artifact:
// release -> flavor -> set of source identity PURLs.
// It is a sibling of the identity inventory (internal/gardenlinux/inventory), differing only in that
// it keeps the per-release, per-flavor breakdown instead of unioning everything.
package flavorinventory

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/glrd"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/packages"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/sbom"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/version"
	"github.com/gardenlinux/glvd2/internal/purl"
)

// PoolFlavor is the fallback flavor used for releases that lacks a complete SBOM set:
// its InRelease pool is release-wide, with no per-flavor breakdown, so the
// per-flavor view degrades gracefully to release-level under this single flavor.
const PoolFlavor = "pool"

// ErrEmptySource reports that a package carried an empty source name.
var ErrEmptySource = errors.New("empty source name")

// Inventory is the version-free per-release, per-flavor source inclusion artifact.
// The release key is the GL version string ("1877.26", "2150.12.0").
// The zero value is not usable; construct it via an Accumulator.
type Inventory struct {
	// byRelease maps a release key to flavor -> set of source identity PURLs.
	byRelease map[string]map[string]purl.VariantMap[struct{}]
}

// Lookup returns the flavors of a release that ship a source or shipped=false when no flavor ships it.
// It is namespace-variant tolerant, such that a source stored under one of deb/gardenlinux
// still matches a query under the other. It returns an error if canonicalSourcePURL cannot be parsed.
func (i Inventory) Lookup(releaseKey, canonicalSourcePURL string) ([]string, bool, error) {
	flavors, ok := i.byRelease[releaseKey]
	if !ok {
		return nil, false, nil
	}

	var shipping []string
	for flavor, sources := range flavors {
		_, has, err := sources.Get(canonicalSourcePURL)
		if err != nil {
			return nil, false, err
		}
		if has {
			shipping = append(shipping, flavor)
		}
	}

	if len(shipping) == 0 {
		return nil, false, nil
	}
	slices.Sort(shipping)

	return shipping, true, nil
}

// AuditRelease is the stable audit structure for one release.
type AuditRelease struct {
	Release string        `json:"release"`
	Flavors []AuditFlavor `json:"flavors"`
}

// AuditFlavor is the stable audit structure for one flavor's source inclusion set.
type AuditFlavor struct {
	Flavor  string   `json:"flavor"`
	Sources []string `json:"sources"`
}

// AuditEntries returns the inventory in a stable structure: Releases, flavors, and source PURLs are all sorted,
// so identical input yields identical serialized bytes and runs diff cleanly.
func (i Inventory) AuditEntries() []AuditRelease {
	out := make([]AuditRelease, 0, len(i.byRelease))
	for _, rel := range slices.Sorted(maps.Keys(i.byRelease)) {
		flavors := i.byRelease[rel]
		entry := AuditRelease{Release: rel, Flavors: make([]AuditFlavor, 0, len(flavors))}
		for _, flavor := range slices.Sorted(maps.Keys(flavors)) {
			sources := slices.Sorted(maps.Keys(flavors[flavor]))
			entry.Flavors = append(entry.Flavors, AuditFlavor{Flavor: flavor, Sources: sources})
		}
		out = append(out, entry)
	}

	return out
}

// inReleaseFetchFunc fetches and parses the package list from the InRelease file.
type inReleaseFetchFunc func(ctx context.Context, release version.GardenLinuxRelease) ([]packages.Package, error)

// Accumulator accumulates the per-release, per-flavor inclusion across the shared
// SBOM pass. It implements [sbom.Consumer]. The zero value is not usable;
// construct it via [NewAccumulator].
type Accumulator struct {
	fetchInRelease inReleaseFetchFunc
	byRelease      map[string]map[string]purl.VariantMap[struct{}]
}

var _ sbom.Consumer = (*Accumulator)(nil)

// Option configures an Accumulator.
type Option func(*Accumulator)

// WithInReleaseFetch overrides InRelease fetching/parsing (for tests).
func WithInReleaseFetch(
	f func(ctx context.Context, release version.GardenLinuxRelease) ([]packages.Package, error),
) Option {
	return func(a *Accumulator) { a.fetchInRelease = f }
}

// NewAccumulator constructs a per-release, per-flavor inclusion accumulator.
func NewAccumulator(opts ...Option) *Accumulator {
	a := &Accumulator{
		fetchInRelease: packages.GetPackageListsFromInRelease,
		byRelease:      make(map[string]map[string]purl.VariantMap[struct{}]),
	}
	for _, opt := range opts {
		opt(a)
	}

	return a
}

// AddSBOM folds one release-flavor SBOM's sources into that flavor's inclusion set.
// A conversion error is a hard failure.
func (a *Accumulator) AddSBOM(release glrd.Release, flavor string, bom *cdx.BOM) error {
	pkgs, err := packages.PackageListFromSBOM(bom)
	if err != nil {
		return fmt.Errorf("converting SBOM: %w", err)
	}

	return a.addPackages(version.ReleaseKey(release), flavor, pkgs)
}

// MissingSBOMSet falls back to the release's InRelease pool, recorded under the
// single [PoolFlavor] sentinel: a release without a complete SBOM set has no
// per-flavor data, so the per-flavor view degrades to release-level.
func (a *Accumulator) MissingSBOMSet(ctx context.Context, release glrd.Release) error {
	slog.Warn("not all flavors of the release have an SBOM; "+
		"falling back to the release InRelease file under the pool sentinel flavor",
		slog.String("release", release.Name))

	pkgs, err := a.fetchInRelease(ctx, version.ReleaseSuite(release))
	if err != nil {
		return fmt.Errorf("fetching InRelease for release %s: %w", release.Name, err)
	}

	return a.addPackages(version.ReleaseKey(release), PoolFlavor, pkgs)
}

// Result returns the assembled inventory.
func (a *Accumulator) Result() Inventory {
	slog.Info("built GL per-release per-flavor source inventory", slog.Int("releases", len(a.byRelease)))

	return Inventory{byRelease: a.byRelease}
}

// addPackages folds each package's source into the (release, flavor) inclusion set.
func (a *Accumulator) addPackages(rel, flavor string, pkgs []packages.Package) error {
	flavors, ok := a.byRelease[rel]
	if !ok {
		flavors = make(map[string]purl.VariantMap[struct{}])
		a.byRelease[rel] = flavors
	}
	sources, ok := flavors[flavor]
	if !ok {
		sources = make(purl.VariantMap[struct{}])
		flavors[flavor] = sources
	}

	for _, pkg := range pkgs {
		if pkg.Source == "" {
			return fmt.Errorf("package %q: %w", pkg.Name, ErrEmptySource)
		}

		identity, err := pkg.IdentityPURL()
		if err != nil {
			return fmt.Errorf("identity PURL for source %q: %w", pkg.Source, err)
		}

		sources[identity] = struct{}{}
	}

	return nil
}
