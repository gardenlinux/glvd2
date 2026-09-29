// Package inventory builds the set of source-name identity PURLs
// that Garden Linux ships, unioned across all currently-maintained releases.
package inventory

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

// defaultMinPURLs is the minimum size for a valid set.
// We should fail, if we get less than this amount, because something went wrong.
const defaultMinPURLs = 100

// ErrBelowThreshold reports that the assembled set is smaller than the sanity threshold.
// Hence, the inventory is degraded and must not be used to gate CVEs.
var ErrBelowThreshold = errors.New("inventory below minimum size")

// ErrEmptySource reports that a package carried an empty source name.
var ErrEmptySource = errors.New("empty source name")

// Set is a set of canonical source-name identity PURLs.
// The zero value is not usable; construct it via an Accumulator.
type Set struct {
	purls map[string]struct{}
}

// Contains reports whether the identity PURL is in the set. It checks the PURL
// under both the debian and gardenlinux namespaces, so a source stored under
// one namespace still matches a query using the other.
// It returns an error if canonicalPURL cannot be parsed into its namespace variants.
func (s Set) Contains(canonicalPURL string) (bool, error) {
	variants, err := purl.NamespaceVariants(canonicalPURL)
	if err != nil {
		return false, fmt.Errorf("deriving namespace variants for %q: %w", canonicalPURL, err)
	}

	for _, v := range variants {
		if _, ok := s.purls[v]; ok {
			return true, nil
		}
	}

	return false, nil
}

// Len returns the number of distinct identity PURLs in the set.
func (s Set) Len() int {
	return len(s.purls)
}

// AuditEntries returns the set's identity PURLs, sorted, for audit output.
func (s Set) AuditEntries() []string {
	out := make([]string, 0, len(s.purls))
	for p := range s.purls {
		out = append(out, p)
	}
	slices.Sort(out)

	return out
}

// inReleaseFetchFunc fetches and parses the package list from the InRelease file.
type inReleaseFetchFunc func(ctx context.Context, release version.GardenLinuxRelease) ([]packages.Package, error)

// Accumulator accumulates the inventory through consuming the SBOMs.
// It implements [sbom.Consumer].
// The zero value is not usable; construct it via [NewAccumulator].
type Accumulator struct {
	minPURLs       int
	fetchInRelease inReleaseFetchFunc
	purls          map[string]struct{}
}

var _ sbom.Consumer = (*Accumulator)(nil)

// Option configures an Accumulator.
type Option func(*Accumulator)

// WithMinPURLs overrides the sanity-threshold floor (for tests).
func WithMinPURLs(n int) Option {
	return func(a *Accumulator) { a.minPURLs = n }
}

// WithInReleaseFetch overrides InRelease fetching/parsing (for tests).
func WithInReleaseFetch(
	f func(ctx context.Context, release version.GardenLinuxRelease) ([]packages.Package, error),
) Option {
	return func(a *Accumulator) { a.fetchInRelease = f }
}

// NewAccumulator constructs an inventory accumulator with the given options.
func NewAccumulator(opts ...Option) *Accumulator {
	a := &Accumulator{
		minPURLs:       defaultMinPURLs,
		fetchInRelease: packages.GetPackageListsFromInRelease,
		purls:          make(map[string]struct{}),
	}
	for _, opt := range opts {
		opt(a)
	}

	return a
}

// AddSBOM folds a release-flavor SBOM's deb packages into the set.
// A conversion error is a hard failure: the inventory gates CVEs and must be trustworthy.
func (a *Accumulator) AddSBOM(bom *cdx.BOM) error {
	pkgs, err := packages.PackageListFromSBOM(bom)
	if err != nil {
		return fmt.Errorf("converting SBOM: %w", err)
	}

	return a.addPackages(pkgs)
}

// MissingSBOMSet falls back to the release's InRelease file
// for a maintained release that lacks a complete SBOM set for all flavors.
func (a *Accumulator) MissingSBOMSet(ctx context.Context, release glrd.Release) error {
	slog.Warn("not all flavors of the release have an SBOM; "+
		"falling back to the release InRelease file",
		slog.String("release", release.Name))

	pkgs, err := a.fetchInRelease(ctx, releaseSuite(release))
	if err != nil {
		return fmt.Errorf("fetching InRelease for release %s: %w", release.Name, err)
	}

	return a.addPackages(pkgs)
}

// Result applies the sanity threshold and returns the assembled set.
func (a *Accumulator) Result() (Set, error) {
	if len(a.purls) < a.minPURLs {
		return Set{}, fmt.Errorf(
			"%w: has %d purls, success threshold %d",
			ErrBelowThreshold, len(a.purls), a.minPURLs,
		)
	}

	slog.Info("built GL package inventory", slog.Int("purls", len(a.purls)))

	return Set{purls: a.purls}, nil
}

// addPackages folds each package's identity PURL into the set.
func (a *Accumulator) addPackages(pkgs []packages.Package) error {
	for _, pkg := range pkgs {
		if pkg.Source == "" {
			return fmt.Errorf("package %q: %w", pkg.Name, ErrEmptySource)
		}

		canon, err := pkg.IdentityPURL()
		if err != nil {
			return fmt.Errorf("identity PURL for source %q: %w", pkg.Source, err)
		}

		a.purls[canon] = struct{}{}
	}

	return nil
}

// releaseSuite converts a GLRD release into the version.GardenLinuxRelease used
// to address package pool. The suite name mirrors the release's version scheme:
// "major.minor" for legacy releases and "major.minor.patch" for semver releases.
func releaseSuite(release glrd.Release) version.GardenLinuxRelease {
	return version.MakeGardenLinuxRelease(release.Version)
}
