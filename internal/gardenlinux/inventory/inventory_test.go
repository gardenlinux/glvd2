package inventory_test

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/glrd"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/inventory"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/packages"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/version"
	"github.com/gardenlinux/glvd2/internal/purl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// contains queries the set and fails the test if the PURL cannot be parsed.
func contains(t *testing.T, set inventory.Set, canonicalPURL string) bool {
	t.Helper()

	ok, err := set.Contains(canonicalPURL)
	require.NoError(t, err)

	return ok
}

// release builds a GLRD release from a version string
// like "1877.3" (legacy) or "2150.8.1" (semver) and the given flavors.
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

	return glrd.Release{Name: ver, Version: v, Flavors: flavors}
}

// bomFromPackages builds a CycloneDX BOM whose deb components should round-trip through
// the real conversion back to the given packages.
func bomFromPackages(pkgs []packages.Package) *cdx.BOM {
	components := make([]cdx.Component, 0, len(pkgs))
	for _, pkg := range pkgs {
		components = append(components, debComponent(pkg))
	}

	return &cdx.BOM{Components: &components}
}

// debComponent builds a deb component whose PURL encodes name, version,
// namespace, architecture, and (when it differs from the name) the source.
func debComponent(pkg packages.Package) cdx.Component {
	namespace := pkg.Namespace
	if namespace == "" {
		namespace = purl.NamespaceDebian
	}
	pkgVersion := pkg.Version
	if pkgVersion == "" {
		pkgVersion = "1.0"
	}

	purlStr := "pkg:deb/" + namespace + "/" + pkg.Name + "@" + pkgVersion
	qualifiers := make([]string, 0, 2)
	if pkg.Architecture != "" {
		qualifiers = append(qualifiers, "arch="+pkg.Architecture)
	}
	if pkg.Source != "" && pkg.Source != pkg.Name {
		qualifiers = append(qualifiers, "upstream="+pkg.Source)
	}
	if len(qualifiers) > 0 {
		purlStr += "?" + strings.Join(qualifiers, "&")
	}

	return cdx.Component{
		Type:       cdx.ComponentTypeLibrary,
		Name:       pkg.Name,
		Version:    pkgVersion,
		PackageURL: purlStr,
	}
}

func TestAccumulator_TwoInventoryItems(t *testing.T) {
	t.Parallel()

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

	s := inventory.NewAccumulator(inventory.WithMinPURLs(1))
	require.NoError(t, s.AddSBOM(bomFromPackages(sbomPkgs)))

	set, err := s.Result()
	require.NoError(t, err)

	assert.Equal(t, 2, set.Len())
	// A gardenlinux-stored source still matches a debian-namespaced query, and vice-versa.
	assert.True(t, contains(t, set, "pkg:deb/debian/glibc"), "debian query hits gardenlinux-stored source")
	assert.True(t, contains(t, set, "pkg:deb/gardenlinux/glibc"), "gardenlinux query hits gardenlinux-stored source")
	assert.True(t, contains(t, set, "pkg:deb/debian/openssl"), "debian query hits debian-stored source")
	assert.True(t, contains(t, set, "pkg:deb/gardenlinux/openssl"), "gardenlinux query hits debian-stored source")
	assert.False(t, contains(t, set, "pkg:deb/debian/wayland"), "unshipped source must be a miss (debian)")
	assert.False(t, contains(t, set, "pkg:deb/gardenlinux/wayland"), "unshipped source must be a miss (gardenlinux)")
}

func TestContains_ContainsWithInvalidPURLReturnsError(t *testing.T) {
	t.Parallel()

	s := inventory.NewAccumulator(inventory.WithMinPURLs(1))
	require.NoError(t, s.AddSBOM(bomFromPackages([]packages.Package{{Name: "libc6", Source: "glibc"}})))
	set, err := s.Result()
	require.NoError(t, err)

	ok, err := set.Contains("not-a-purl")
	require.Error(t, err)
	assert.False(t, ok)
}

// A conversion failure (here, an unclassifiable component - a coverage gap)
// aborts AddSBOM.
func TestAccumulator_HardFailsOnSBOMConversionError(t *testing.T) {
	t.Parallel()

	// A package-like component without a PURL is unclassifiable.
	components := []cdx.Component{{Type: cdx.ComponentTypeLibrary, Name: "mystery"}}

	s := inventory.NewAccumulator(inventory.WithMinPURLs(1))
	err := s.AddSBOM(&cdx.BOM{Components: &components})
	require.Error(t, err)
}

func TestAccumulator_FallsBackToInReleaseOnMissingSBOMSet(t *testing.T) {
	t.Parallel()

	inRelPkgs := []packages.Package{
		{Name: "libc6", Source: "glibc"},
		{Name: "bash", Source: "bash"},
	}

	var gotRelease version.GardenLinuxRelease
	s := inventory.NewAccumulator(
		inventory.WithMinPURLs(1),
		inventory.WithInReleaseFetch(
			func(_ context.Context, r version.GardenLinuxRelease) ([]packages.Package, error) {
				gotRelease = r

				return inRelPkgs, nil
			}),
	)
	require.NoError(t, s.MissingSBOMSet(t.Context(), release(t, "1877.3", "metal-amd64")))

	set, err := s.Result()
	require.NoError(t, err)

	assert.Equal(t, "1877.3", gotRelease.Name, "right fallback release name")
	assert.True(t, contains(t, set, "pkg:deb/debian/glibc"))
	assert.True(t, contains(t, set, "pkg:deb/debian/bash"))
}

func TestAccumulator_UnionsAcrossSBOMs(t *testing.T) {
	t.Parallel()

	s := inventory.NewAccumulator(inventory.WithMinPURLs(1))
	require.NoError(t, s.AddSBOM(bomFromPackages([]packages.Package{{Name: "libc6", Source: "glibc"}})))
	require.NoError(t, s.AddSBOM(bomFromPackages([]packages.Package{{Name: "libssl3", Source: "openssl"}})))
	require.NoError(t, s.AddSBOM(bomFromPackages([]packages.Package{{Name: "libc6", Source: "glibc"}}))) // duplicate

	set, err := s.Result()
	require.NoError(t, err)

	assert.Equal(t, 2, set.Len(), "duplicate sources dedupe")
	assert.True(t, contains(t, set, "pkg:deb/debian/glibc"))
	assert.True(t, contains(t, set, "pkg:deb/debian/openssl"))
}

// One release feeds an SBOM, another has none and falls back to InRelease;
// both accumulators contribute to the merged set.
func TestAccumulator_MixedSBOMAndInRelease(t *testing.T) {
	t.Parallel()

	s := inventory.NewAccumulator(
		inventory.WithMinPURLs(1),
		inventory.WithInReleaseFetch(
			func(_ context.Context, _ version.GardenLinuxRelease) ([]packages.Package, error) {
				return []packages.Package{{Name: "bash", Source: "bash"}}, nil
			}),
	)
	require.NoError(t, s.AddSBOM(bomFromPackages([]packages.Package{{Name: "libc6", Source: "glibc"}})))
	require.NoError(t, s.MissingSBOMSet(t.Context(), release(t, "1877.1", "metal-amd64")))

	set, err := s.Result()
	require.NoError(t, err)

	assert.Equal(t, 2, set.Len())
	assert.True(t, contains(t, set, "pkg:deb/debian/glibc"), "from SBOM release")
	assert.True(t, contains(t, set, "pkg:deb/debian/bash"), "from InRelease fallback")
}

// An empty source can only reach the set via the InRelease path;
// SBOM conversion always resolves a non-empty source (falling back to the binary name).
func TestAccumulator_HardFailsOnEmptySource(t *testing.T) {
	t.Parallel()

	s := inventory.NewAccumulator(
		inventory.WithMinPURLs(1),
		inventory.WithInReleaseFetch(
			func(_ context.Context, _ version.GardenLinuxRelease) ([]packages.Package, error) {
				return []packages.Package{{Name: "libc6", Source: ""}}, nil
			}),
	)
	err := s.MissingSBOMSet(t.Context(), release(t, "1877.0", "metal-amd64"))
	require.ErrorIs(t, err, inventory.ErrEmptySource)
}

func TestAccumulator_HardFailsOnInReleaseFetchError(t *testing.T) {
	t.Parallel()

	fetchErr := errors.New("pool unreachable")
	s := inventory.NewAccumulator(
		inventory.WithInReleaseFetch(
			func(_ context.Context, _ version.GardenLinuxRelease) ([]packages.Package, error) {
				return nil, fetchErr
			}),
	)
	err := s.MissingSBOMSet(t.Context(), release(t, "1877.0", "metal-amd64"))
	require.ErrorIs(t, err, fetchErr)
}

func TestAccumulator_HardFailsBelowThreshold(t *testing.T) {
	t.Parallel()

	s := inventory.NewAccumulator(inventory.WithMinPURLs(100))
	require.NoError(t, s.AddSBOM(bomFromPackages([]packages.Package{{Name: "libc6", Source: "glibc"}})))

	_, err := s.Result()
	require.ErrorIs(t, err, inventory.ErrBelowThreshold)
}

func TestAccumulator_HardFailsOnEmptyInventory(t *testing.T) {
	t.Parallel()

	_, err := inventory.NewAccumulator().Result()
	require.ErrorIs(t, err, inventory.ErrBelowThreshold)
}
