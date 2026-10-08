// Package shippedversions builds the per-release index of the versioned source packages
// Garden Linux ships.
package shippedversions

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/glrd"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/packages"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/sbom"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/version"
	"github.com/gardenlinux/glvd2/internal/purl"
)

// defaultMinPerRelease is the minimum number of shipped sources for a release to
// be considered valid. A smaller index means something went wrong (a truncated
// pool, a bad fetch) and must not be trusted to gate CVEs.
const defaultMinPerRelease = 100

// ErrBelowThreshold reports that a release's index is smaller than the sanity threshold.
var ErrBelowThreshold = errors.New("release index below minimum size")

// ErrEmptySource reports that a package carried an empty source name.
var ErrEmptySource = errors.New("empty source name")

// ErrEmptySourceVersion reports that a package carried an empty source version.
var ErrEmptySourceVersion = errors.New("empty source version")

// ErrMultipleVersions reports that two distinct source versions appeared for one
// source in a single release. Garden Linux ships a single pool per release, so
// this is an anomaly, not a normal multi-version case.
var ErrMultipleVersions = errors.New("multiple source versions for one source in a release")

// Index is the per-release versioned source index.
// The release key is the GL version string like "1877.26" or "2150.12.0".
// The zero value is not usable; construct it via an Accumulator.
type Index struct {
	// byRelease maps a release key to its source identity PURL -> versioned PURL map.
	byRelease map[string]purl.VariantMap[string]
}

// Lookup returns the shipped versioned source PURL for a source in a release or
// shipped=false when the release ships no such source. It is namespace-variant
// tolerant: a source stored under one of deb/gardenlinux still matches a query
// under the other. It returns an error if canonicalSourcePURL cannot be parsed.
func (i Index) Lookup(releaseKey, canonicalSourcePURL string) (string, bool, error) {
	sources, ok := i.byRelease[releaseKey]
	if !ok {
		return "", false, nil
	}

	versioned, ok, err := sources.Get(canonicalSourcePURL)
	if err != nil {
		return "", false, err
	}

	return versioned, ok, nil
}

// Releases returns the release keys in the index, sorted.
func (i Index) Releases() []string {
	out := make([]string, 0, len(i.byRelease))
	for r := range i.byRelease {
		out = append(out, r)
	}
	slices.Sort(out)

	return out
}

// inReleaseFetchFunc fetches and parses the package list from the InRelease file.
type inReleaseFetchFunc func(ctx context.Context, release version.GardenLinuxRelease) ([]packages.Package, error)

// Accumulator accumulates the per-release versioned index across the shared SBOM pass.
// It implements [sbom.Consumer]. The zero value is not usable; construct it via [NewAccumulator].
type Accumulator struct {
	minPerRelease  int
	fetchInRelease inReleaseFetchFunc
	// byRelease maps a release key to its source identity PURL -> versioned entry.
	byRelease map[string]purl.VariantMap[entry]
}

type entry struct {
	versionedPURL string
	sourceVersion string
}

var _ sbom.Consumer = (*Accumulator)(nil)

// Option configures an Accumulator.
type Option func(*Accumulator)

// WithMinPerRelease overrides the per-release sanity-threshold floor (useful for tests).
func WithMinPerRelease(n int) Option {
	return func(a *Accumulator) { a.minPerRelease = n }
}

// WithInReleaseFetch overrides InRelease fetching/parsing (useful for tests).
func WithInReleaseFetch(
	f func(ctx context.Context, release version.GardenLinuxRelease) ([]packages.Package, error),
) Option {
	return func(a *Accumulator) { a.fetchInRelease = f }
}

// NewAccumulator constructs a per-release versioned-index accumulator.
func NewAccumulator(opts ...Option) *Accumulator {
	a := &Accumulator{
		minPerRelease:  defaultMinPerRelease,
		fetchInRelease: packages.GetPackageListsFromInRelease,
		byRelease:      make(map[string]purl.VariantMap[entry]),
	}
	for _, opt := range opts {
		opt(a)
	}

	return a
}

// AddSBOM folds one release-flavor SBOM into the release's versioned index.
// flavor is unused, since every flavor draws from the same pool,
// so a source has only one version per release regardless of flavor.
func (a *Accumulator) AddSBOM(release glrd.Release, _ string, bom *cdx.BOM) error {
	pkgs, err := packages.PackageListFromSBOM(bom)
	if err != nil {
		return fmt.Errorf("converting SBOM: %w", err)
	}

	return a.addPackages(version.ReleaseKey(release), pkgs)
}

// MissingSBOMSet falls back to the release's InRelease pool.
func (a *Accumulator) MissingSBOMSet(ctx context.Context, release glrd.Release) error {
	slog.Warn("not all flavors of the release have an SBOM; "+
		"falling back to the release InRelease file for versioned index",
		slog.String("release", release.Name))

	pkgs, err := a.fetchInRelease(ctx, version.ReleaseSuite(release))
	if err != nil {
		return fmt.Errorf("fetching InRelease for release %s: %w", release.Name, err)
	}

	return a.addPackages(version.ReleaseKey(release), pkgs)
}

// Result applies the per-release floor and returns the assembled index.
func (a *Accumulator) Result() (Index, error) {
	byRelease := make(map[string]purl.VariantMap[string], len(a.byRelease))
	for rel, sources := range a.byRelease {
		if len(sources) < a.minPerRelease {
			return Index{}, fmt.Errorf(
				"%w: release %s has %d sources, success threshold %d",
				ErrBelowThreshold, rel, len(sources), a.minPerRelease,
			)
		}

		versioned := make(purl.VariantMap[string], len(sources))
		for key, e := range sources {
			versioned[key] = e.versionedPURL
		}
		byRelease[rel] = versioned
	}

	slog.Info("built per-release versioned source index", slog.Int("releases", len(byRelease)))

	return Index{byRelease: byRelease}, nil
}

// addPackages folds each package's shipped source version into the release index,
// failing hard when a source would receive a second, distinct source version.
func (a *Accumulator) addPackages(rel string, pkgs []packages.Package) error {
	sources, ok := a.byRelease[rel]
	if !ok {
		sources = make(purl.VariantMap[entry])
		a.byRelease[rel] = sources
	}

	for _, pkg := range pkgs {
		if pkg.Source == "" {
			return fmt.Errorf("package %q: %w", pkg.Name, ErrEmptySource)
		}
		if pkg.SourceVersion == "" {
			return fmt.Errorf("source %q: %w", pkg.Source, ErrEmptySourceVersion)
		}

		identity, err := pkg.IdentityPURL()
		if err != nil {
			return fmt.Errorf("identity PURL for source %q: %w", pkg.Source, err)
		}

		versioned, err := pkg.VersionedIdentityPURL()
		if err != nil {
			return fmt.Errorf("versioned PURL for source %q: %w", pkg.Source, err)
		}

		// Probe both namespace variants so a source arriving under deb and gardenlinux
		// in one release is still recognised as the same source.
		existing, seen, err := sources.Get(identity)
		if err != nil {
			return fmt.Errorf("probing namespace variants for source %q: %w", pkg.Source, err)
		}
		if seen {
			if existing.sourceVersion != pkg.SourceVersion {
				return fmt.Errorf("%w: release %s source %q has %q and %q",
					ErrMultipleVersions, rel, pkg.Source, existing.sourceVersion, pkg.SourceVersion)
			}

			continue
		}

		sources[identity] = entry{versionedPURL: versioned, sourceVersion: pkg.SourceVersion}
	}

	return nil
}
