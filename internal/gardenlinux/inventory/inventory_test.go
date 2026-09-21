package inventory_test

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/gardenlinux/glvd2/internal/gardenlinux/glrd"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/inventory"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/packages"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/version"
	"github.com/gardenlinux/glvd2/internal/purl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeLister returns a fixed set of releases.
type fakeLister struct {
	releases []glrd.Release
	err      error
}

func (f fakeLister) GetMaintainedReleases(_ context.Context) ([]glrd.Release, error) {
	return f.releases, f.err
}

// contains queries the set and fails the test if the PURL cannot be parsed.
func contains(t *testing.T, set *inventory.Set, canonicalPURL string) bool {
	t.Helper()

	ok, err := set.Contains(canonicalPURL)
	require.NoError(t, err)

	return ok
}

// release builds a GLRD release from a version string like "1877.3" (legacy)
// or "2150.8.1" (semver) and the given flavors.
func release(t *testing.T, ver string, flavors ...string) glrd.Release {
	t.Helper()

	parts := strings.Split(ver, ".")
	require.GreaterOrEqual(t, len(parts), 2, "version needs at least major.minor")
	require.LessOrEqual(t, len(parts), 3, "version has at most major.minor.patch")

	nums := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		require.NoErrorf(t, err, "parsing version part %q", p)
		nums[i] = n
	}

	v := glrd.Version{Major: nums[0], Minor: nums[1]}
	if len(parts) == 3 {
		v.Patch = nums[2]
	}

	return glrd.Release{Name: "test", Version: v, Flavors: flavors}
}

// testOpts sets a tiny threshold to keep tests hermetic.
func testOpts(extra ...inventory.Option) []inventory.Option {
	base := make([]inventory.Option, 0, 1+len(extra))
	base = append(base, inventory.WithMinPURLs(1))

	return append(base, extra...)
}

// sbomLocator resolves every flavor to a per-flavor URL.
func sbomLocator() inventory.Option {
	return inventory.WithSBOMLocator(func(_ glrd.Release, flavor string) (*url.URL, error) {
		return &url.URL{Scheme: "https", Host: "example", Path: "/" + flavor}, nil
	})
}

func TestBuild_JoinAgainstFixtureInventory(t *testing.T) {
	t.Parallel()

	// An SBOM ships binary libc6 with source glibc:
	// a Debian match on source glibc is a hit, wayland a miss.
	sbomPkgs := []packages.Package{
		{
			Name:         "libc6",
			Source:       "glibc",
			Version:      "2.31-13",
			Architecture: "amd64",
			Namespace:    purl.NamespaceGardenLinux,
		},
		{
			Name:         "libssl3",
			Source:       "openssl",
			Version:      "3.0.11-1",
			Architecture: "amd64",
			Namespace:    purl.NamespaceDebian,
		},
	}

	set, err := inventory.Build(
		context.Background(),
		fakeLister{releases: []glrd.Release{release(t, "1877.0", "kvm-amd64")}},
		testOpts(
			sbomLocator(),
			inventory.WithSBOMFetch(func(_ context.Context, _ *url.URL) ([]packages.Package, error) {
				return sbomPkgs, nil
			}),
		)...,
	)
	require.NoError(t, err)

	assert.Equal(t, 2, set.Len())
	// A gardenlinux-stored source still matches a debian-namespaced query, and vice-versa.
	assert.True(t, contains(t, set, "pkg:deb/debian/glibc"), "debian query hits gardenlinux-stored source")
	assert.True(t, contains(t, set, "pkg:deb/gardenlinux/glibc"), "gardenlinux query hits gardenlinux-stored source")
	assert.True(t, contains(t, set, "pkg:deb/debian/openssl"), "debian query hits debian-stored source")
	assert.True(t, contains(t, set, "pkg:deb/gardenlinux/openssl"), "gardenlinux query hits debian-stored source")
	assert.False(t, contains(t, set, "pkg:deb/debian/wayland"), "unshipped source must be a miss")
}

func TestContains_InvalidPURLReturnsError(t *testing.T) {
	t.Parallel()

	pkgs := []packages.Package{{Name: "libc6", Source: "glibc"}}
	set, err := inventory.Build(
		context.Background(),
		fakeLister{releases: []glrd.Release{release(t, "1877.3", "metal-amd64")}},
		testOpts(
			sbomLocator(),
			inventory.WithSBOMFetch(func(_ context.Context, _ *url.URL) ([]packages.Package, error) {
				return pkgs, nil
			}),
		)...,
	)
	require.NoError(t, err)

	ok, err := set.Contains("not-a-purl")
	require.Error(t, err)
	assert.False(t, ok)
}

// The InRelease fallback fires when no SBOM exists, and the suite handed to the fetcher
// is derived from the release version (formatting itself is covered by version_test).
func TestBuild_FallsBackToInReleaseWhenNoSBOM(t *testing.T) {
	t.Parallel()

	inRelPkgs := []packages.Package{
		{Name: "libc6", Source: "glibc"},
		{Name: "bash", Source: "bash"},
	}

	var gotRelease version.GardenLinuxRelease
	set, err := inventory.Build(
		context.Background(),
		fakeLister{releases: []glrd.Release{release(t, "1877.3", "metal-amd64")}},
		testOpts(
			inventory.WithSBOMLocator(func(_ glrd.Release, _ string) (*url.URL, error) {
				return nil, glrd.ErrNoSBOM // no SBOM for this release
			}),
			inventory.WithInReleaseFetch(
				func(_ context.Context, r version.GardenLinuxRelease) ([]packages.Package, error) {
					gotRelease = r

					return inRelPkgs, nil
				}),
		)...,
	)
	require.NoError(t, err)

	assert.Equal(t, "1877.3", gotRelease.Name, "fallback suite comes from the release version")
	assert.True(t, contains(t, set, "pkg:deb/debian/glibc"))
	assert.True(t, contains(t, set, "pkg:deb/debian/bash"))
}

func TestBuild_UnionsAcrossReleasesAndFlavors(t *testing.T) {
	t.Parallel()

	byFlavor := map[string][]packages.Package{
		"kvm-amd64":   {{Name: "libc6", Source: "glibc"}},
		"metal-arm64": {{Name: "libssl3", Source: "openssl"}},
		"cloud-amd64": {{Name: "libc6", Source: "glibc"}}, // duplicate source
	}

	set, err := inventory.Build(
		context.Background(),
		fakeLister{releases: []glrd.Release{
			release(t, "1877.0", "kvm-amd64", "metal-arm64"),
			release(t, "1877.1", "cloud-amd64"),
		}},
		testOpts(
			sbomLocator(),
			inventory.WithSBOMFetch(func(_ context.Context, u *url.URL) ([]packages.Package, error) {
				return byFlavor[u.Path[1:]], nil
			}),
		)...,
	)
	require.NoError(t, err)

	assert.Equal(t, 2, set.Len(), "duplicate sources dedupe")
	assert.True(t, contains(t, set, "pkg:deb/debian/glibc"))
	assert.True(t, contains(t, set, "pkg:deb/debian/openssl"))
}

// One release publishes an SBOM, another has none and falls back to InRelease;
// both projections contribute to the merged set.
func TestBuild_MixedSBOMAndInReleaseAcrossReleases(t *testing.T) {
	t.Parallel()

	set, err := inventory.Build(
		context.Background(),
		fakeLister{releases: []glrd.Release{
			release(t, "1877.0", "kvm-amd64"),
			release(t, "1877.1", "metal-amd64"),
		}},
		testOpts(
			inventory.WithSBOMLocator(func(_ glrd.Release, flavor string) (*url.URL, error) {
				if flavor == "kvm-amd64" {
					return &url.URL{Scheme: "https", Host: "example", Path: "/sbom"}, nil
				}

				return nil, glrd.ErrNoSBOM
			}),
			inventory.WithSBOMFetch(func(_ context.Context, _ *url.URL) ([]packages.Package, error) {
				return []packages.Package{{Name: "libc6", Source: "glibc"}}, nil
			}),
			inventory.WithInReleaseFetch(
				func(_ context.Context, _ version.GardenLinuxRelease) ([]packages.Package, error) {
					return []packages.Package{{Name: "bash", Source: "bash"}}, nil
				}),
		)...,
	)
	require.NoError(t, err)

	assert.Equal(t, 2, set.Len())
	assert.True(t, contains(t, set, "pkg:deb/debian/glibc"), "from SBOM release")
	assert.True(t, contains(t, set, "pkg:deb/debian/bash"), "from InRelease fallback")
}

// When any flavor of a release lacks an SBOM, the release does not use the partial per-flavor SBOMs;a
// it falls back to the release InRelease file, which is per release and a superset of every flavor's contents.
func TestBuild_PartialFlavorSBOMFallsBackToInRelease(t *testing.T) {
	t.Parallel()

	inReleaseCalled := false
	sbomFetched := false
	set, err := inventory.Build(
		context.Background(),
		fakeLister{releases: []glrd.Release{release(t, "1877.0", "has-sbom", "no-sbom")}},
		testOpts(
			inventory.WithSBOMLocator(func(_ glrd.Release, flavor string) (*url.URL, error) {
				if flavor == "has-sbom" {
					return &url.URL{Scheme: "https", Host: "example", Path: "/sbom"}, nil
				}

				return nil, glrd.ErrNoSBOM
			}),
			inventory.WithSBOMFetch(func(_ context.Context, _ *url.URL) ([]packages.Package, error) {
				sbomFetched = true

				return []packages.Package{{Name: "libc6", Source: "glibc"}}, nil
			}),
			inventory.WithInReleaseFetch(
				func(_ context.Context, _ version.GardenLinuxRelease) ([]packages.Package, error) {
					inReleaseCalled = true

					return []packages.Package{{Name: "bash", Source: "bash"}}, nil
				}),
		)...,
	)
	require.NoError(t, err)

	assert.True(t, inReleaseCalled, "release missing an SBOM for any flavor must fall back to InRelease")
	assert.False(t, sbomFetched, "partial per-flavor SBOMs must not be fetched on the fallback path")
	assert.Equal(t, 1, set.Len())
	assert.True(t, contains(t, set, "pkg:deb/debian/bash"), "from InRelease fallback")
	assert.False(t, contains(t, set, "pkg:deb/debian/glibc"), "partial SBOM contents must not leak in")
}

// A release with no flavors has no SBOMs, so it falls back to InRelease.
func TestBuild_NoFlavorsFallsBackToInRelease(t *testing.T) {
	t.Parallel()

	inReleaseCalled := false
	set, err := inventory.Build(
		context.Background(),
		fakeLister{releases: []glrd.Release{release(t, "1877.0")}},
		testOpts(
			sbomLocator(),
			inventory.WithInReleaseFetch(
				func(_ context.Context, _ version.GardenLinuxRelease) ([]packages.Package, error) {
					inReleaseCalled = true

					return []packages.Package{{Name: "bash", Source: "bash"}}, nil
				}),
		)...,
	)
	require.NoError(t, err)

	assert.True(t, inReleaseCalled, "release with no flavors must fall back to InRelease")
	assert.True(t, contains(t, set, "pkg:deb/debian/bash"))
}

func TestBuild_HardFailsOnEmptySource(t *testing.T) {
	t.Parallel()

	_, err := inventory.Build(
		context.Background(),
		fakeLister{releases: []glrd.Release{release(t, "1877.0", "kvm-amd64")}},
		testOpts(
			sbomLocator(),
			inventory.WithSBOMFetch(func(_ context.Context, _ *url.URL) ([]packages.Package, error) {
				return []packages.Package{{Name: "libc6", Source: ""}}, nil
			}),
		)...,
	)
	require.ErrorIs(t, err, inventory.ErrEmptySource)
}

func TestBuild_HardFailsOnSBOMLocatorError(t *testing.T) {
	t.Parallel()

	locatorErr := errors.New("cannot build SBOM URL")
	_, err := inventory.Build(
		context.Background(),
		fakeLister{releases: []glrd.Release{release(t, "1877.0", "kvm-amd64")}},
		testOpts(
			inventory.WithSBOMLocator(func(_ glrd.Release, _ string) (*url.URL, error) {
				return nil, locatorErr
			}),
		)...,
	)
	require.ErrorIs(t, err, locatorErr)
}

func TestBuild_HardFailsOnSBOMFetchError(t *testing.T) {
	t.Parallel()

	fetchErr := errors.New("network down")
	_, err := inventory.Build(
		context.Background(),
		fakeLister{releases: []glrd.Release{release(t, "1877.0", "kvm-amd64")}},
		testOpts(
			sbomLocator(),
			inventory.WithSBOMFetch(func(_ context.Context, _ *url.URL) ([]packages.Package, error) {
				return nil, fetchErr
			}),
		)...,
	)
	require.ErrorIs(t, err, fetchErr)
}

func TestBuild_HardFailsOnInReleaseFetchError(t *testing.T) {
	t.Parallel()

	fetchErr := errors.New("pool unreachable")
	_, err := inventory.Build(
		context.Background(),
		fakeLister{releases: []glrd.Release{release(t, "1877.0", "metal-amd64")}},
		testOpts(
			inventory.WithSBOMLocator(func(_ glrd.Release, _ string) (*url.URL, error) {
				return nil, glrd.ErrNoSBOM
			}),
			inventory.WithInReleaseFetch(
				func(_ context.Context, _ version.GardenLinuxRelease) ([]packages.Package, error) {
					return nil, fetchErr
				}),
		)...,
	)
	require.ErrorIs(t, err, fetchErr)
}

func TestBuild_HardFailsBelowThreshold(t *testing.T) {
	t.Parallel()

	_, err := inventory.Build(
		context.Background(),
		fakeLister{releases: []glrd.Release{release(t, "1877.0", "kvm-amd64")}},
		inventory.WithMinPURLs(100),
		sbomLocator(),
		inventory.WithSBOMFetch(func(_ context.Context, _ *url.URL) ([]packages.Package, error) {
			return []packages.Package{{Name: "libc6", Source: "glibc"}}, nil
		}),
	)
	require.ErrorIs(t, err, inventory.ErrBelowThreshold)
}

func TestBuild_HardFailsOnEmptyInventory(t *testing.T) {
	t.Parallel()

	_, err := inventory.Build(
		context.Background(),
		fakeLister{releases: nil},
		testOpts()...,
	)
	require.ErrorIs(t, err, inventory.ErrBelowThreshold)
}

func TestBuild_HardFailsWhenListerErrors(t *testing.T) {
	t.Parallel()

	listErr := errors.New("glrd unavailable")
	_, err := inventory.Build(
		context.Background(),
		fakeLister{err: listErr},
		testOpts()...,
	)
	require.ErrorIs(t, err, listErr)
}
