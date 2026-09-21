// Package inventory builds the set of source-name identity PURLs
// that Garden Linux ships, unioned across all currently-supported releases.
package inventory

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"

	"github.com/gardenlinux/glvd2/internal/gardenlinux/glrd"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/packages"
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
// The zero value is not usable; construct it via Build.
type Set struct {
	purls map[string]struct{}
}

// Contains reports whether the identity PURL is in the set. It checks the PURL
// under both the debian and gardenlinux namespaces, so a source stored under
// one namespace still matches a query using the other.
// It returns an error if canonicalPURL cannot be parsed into its namespace variants.
func (s *Set) Contains(canonicalPURL string) (bool, error) {
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
func (s *Set) Len() int {
	return len(s.purls)
}

// ReleaseLister provides the maintained Garden Linux releases to build the set from.
type ReleaseLister interface {
	GetMaintainedReleases(ctx context.Context) ([]glrd.Release, error)
}

// sbomLocatorFunc resolves the SBOM URL for a release flavor.
// It returns glrd.ErrNoSBOM when no SBOM exists, so the caller falls back to InRelease.
type sbomLocatorFunc func(release glrd.Release, flavor string) (*url.URL, error)

// sbomFetchFunc fetches and parses the package list from a CycloneDX SBOM.
type sbomFetchFunc func(ctx context.Context, sbomURL *url.URL) ([]packages.Package, error)

// inReleaseFetchFunc fetches and parses the package list from the InRelease file.
type inReleaseFetchFunc func(ctx context.Context, release version.GardenLinuxRelease) ([]packages.Package, error)

// builder holds the configuration used to assemble a Set.
type builder struct {
	lister         ReleaseLister
	minPURLs       int
	locateSBOM     sbomLocatorFunc
	fetchSBOM      sbomFetchFunc
	fetchInRelease inReleaseFetchFunc
}

// Option configures a Build call.
type Option func(*builder)

// WithMinPURLs overrides the sanity-threshold floor (for tests).
func WithMinPURLs(n int) Option {
	return func(b *builder) { b.minPURLs = n }
}

// WithSBOMLocator overrides SBOM-URL resolution (for tests).
func WithSBOMLocator(f func(release glrd.Release, flavor string) (*url.URL, error)) Option {
	return func(b *builder) { b.locateSBOM = f }
}

// WithSBOMFetch overrides SBOM fetching/parsing (for tests).
func WithSBOMFetch(f func(ctx context.Context, sbomURL *url.URL) ([]packages.Package, error)) Option {
	return func(b *builder) { b.fetchSBOM = f }
}

// WithInReleaseFetch overrides InRelease fetching/parsing (for tests).
func WithInReleaseFetch(
	f func(ctx context.Context, release version.GardenLinuxRelease) ([]packages.Package, error),
) Option {
	return func(b *builder) { b.fetchInRelease = f }
}

// Build assembles the set over all currently-maintained releases, using the
// given release lister. It returns an error on any fetch/parse failure or if
// the set is below the minimum size.
func Build(ctx context.Context, lister ReleaseLister, opts ...Option) (*Set, error) {
	b := &builder{
		lister:         lister,
		minPURLs:       defaultMinPURLs,
		locateSBOM:     func(r glrd.Release, flavor string) (*url.URL, error) { return r.LocateSBOM(flavor) },
		fetchSBOM:      packages.GetPackageListsFromCycloneDx,
		fetchInRelease: packages.GetPackageListsFromInRelease,
	}
	for _, opt := range opts {
		opt(b)
	}

	return b.build(ctx)
}

// build performs the assembly with the resolved configuration.
func (b *builder) build(ctx context.Context) (*Set, error) {
	releases, err := b.lister.GetMaintainedReleases(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing releases: %w", err)
	}

	set := &Set{purls: make(map[string]struct{})}

	for _, release := range releases {
		pkgs, pkgErr := b.packagesForRelease(ctx, release)
		if pkgErr != nil {
			return nil, fmt.Errorf("collecting packages for release %s: %w", release.Name, pkgErr)
		}

		for _, pkg := range pkgs {
			if pkg.Source == "" {
				return nil, fmt.Errorf("release %s: %w", release.Name, ErrEmptySource)
			}
			canon, idErr := pkg.IdentityPURL()
			if idErr != nil {
				return nil, fmt.Errorf("identity PURL for source %q in release %s: %w", pkg.Source, release.Name, idErr)
			}
			set.purls[canon] = struct{}{}
		}
	}

	if set.Len() < b.minPURLs {
		return nil, fmt.Errorf(
			"%w: has %d purls, success threshold %d",
			ErrBelowThreshold, set.Len(), b.minPURLs,
		)
	}

	slog.Info("built GL package inventory", slog.Int("purls", set.Len()))

	return set, nil
}

// packagesForRelease collects the release's packages. It uses the per-flavor SBOMs (unioned)
// only when every flavor has one; otherwise it falls back to the release's InRelease file.
func (b *builder) packagesForRelease(ctx context.Context, release glrd.Release) ([]packages.Package, error) {
	sbomURLs := make([]*url.URL, 0, len(release.Flavors))
	allHaveSBOMs := len(release.Flavors) > 0 // fall back to InRelease, if there are no flavors

	for _, flavor := range release.Flavors {
		sbomURL, err := b.locateSBOM(release, flavor)
		if errors.Is(err, glrd.ErrNoSBOM) {
			allHaveSBOMs = false
			break
		}
		if err != nil {
			return nil, fmt.Errorf("resolving SBOM URL for flavor %q: %w", flavor, err)
		}

		sbomURLs = append(sbomURLs, sbomURL)
	}

	if allHaveSBOMs {
		var result []packages.Package
		for _, sbomURL := range sbomURLs {
			pkgs, err := b.fetchSBOM(ctx, sbomURL)
			if err != nil {
				return nil, fmt.Errorf("fetching SBOM: %w", err)
			}

			result = append(result, pkgs...)
		}

		return result, nil
	}

	slog.Warn("not all flavors of the release have an SBOM; "+
		"falling back to the release InRelease file",
		slog.String("release", release.Name))

	glRelease := releaseSuite(release)
	pkgs, err := b.fetchInRelease(ctx, glRelease)
	if err != nil {
		return nil, fmt.Errorf("fetching InRelease: %w", err)
	}

	return pkgs, nil
}

// releaseSuite converts a GLRD release into the version.GardenLinuxRelease used
// to address package pool. The suite name mirrors the release's version scheme:
// "major.minor" for legacy releases and "major.minor.patch" for semver releases.
func releaseSuite(release glrd.Release) version.GardenLinuxRelease {
	return version.MakeGardenLinuxRelease(release.Version)
}
