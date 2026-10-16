package shippedversions_test

import (
	"context"
	"errors"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/gltest"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/packages"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/shippedversions"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/version"
	"github.com/gardenlinux/glvd2/internal/purl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// debComponent builds a deb component carrying the source name
// and (when set) the source version via the upstream qualifier.
func debComponent(name, source, binVer, srcVer, namespace, arch string) cdx.Component {
	return gltest.DebComponent(packages.Package{
		Name:          name,
		Source:        source,
		Version:       binVer,
		SourceVersion: srcVer,
		Namespace:     namespace,
		Architecture:  arch,
	})
}

func TestAccumulator_SBOMVersionedIndex(t *testing.T) {
	t.Parallel()

	s := shippedversions.NewAccumulator(shippedversions.WithMinPerRelease(1))
	require.NoError(t, s.AddSBOM(gltest.Release(t, "1877.3", "kvm"), "kvm", gltest.BOM(
		// Explicit source version from the upstream qualifier, differing from the binary version.
		debComponent("libc6", "glibc", "2.31-13+b1", "2.31-13", purl.NamespaceGardenLinux, "amd64"),
		// No explicit source version: binary version is the source version.
		debComponent("openssl", "openssl", "3.0.11-1", "", purl.NamespaceDebian, "amd64"),
	)))

	idx, err := s.Result()
	require.NoError(t, err)

	versioned, shipped, err := idx.Lookup("1877.3", "pkg:deb/debian/glibc")
	require.NoError(t, err)
	assert.True(t, shipped)
	assert.Equal(t, "pkg:deb/gardenlinux/glibc@2.31-13", versioned, "explicit source version kept")

	versioned, shipped, err = idx.Lookup("1877.3", "pkg:deb/debian/openssl")
	require.NoError(t, err)
	assert.True(t, shipped)
	assert.Equal(t, "pkg:deb/debian/openssl@3.0.11-1", versioned, "binary version is the source version")
}

func TestLookup_NamespaceVariantTolerant(t *testing.T) {
	t.Parallel()

	s := shippedversions.NewAccumulator(shippedversions.WithMinPerRelease(1))
	require.NoError(t, s.AddSBOM(gltest.Release(t, "1877.3", "kvm"), "kvm", gltest.BOM(
		debComponent("libc6", "glibc", "2.31-13", "", purl.NamespaceGardenLinux, "amd64"),
	)))

	idx, err := s.Result()
	require.NoError(t, err)

	// A gardenlinux-stored source matches a debian-namespaced query and vice-versa.
	for _, q := range []string{"pkg:deb/debian/glibc", "pkg:deb/gardenlinux/glibc"} {
		versioned, shipped, lookupErr := idx.Lookup("1877.3", q)
		require.NoError(t, lookupErr)
		assert.True(t, shipped, "query %q must hit", q)
		assert.Equal(t, "pkg:deb/gardenlinux/glibc@2.31-13", versioned)
	}
}

func TestLookup_NotShipped(t *testing.T) {
	t.Parallel()

	s := shippedversions.NewAccumulator(shippedversions.WithMinPerRelease(1))
	require.NoError(t, s.AddSBOM(gltest.Release(t, "1877.3", "kvm"), "kvm", gltest.BOM(
		debComponent("libc6", "glibc", "2.31-13", "", purl.NamespaceDebian, "amd64"),
	)))

	idx, err := s.Result()
	require.NoError(t, err)

	_, shipped, err := idx.Lookup("1877.3", "pkg:deb/debian/wayland")
	require.NoError(t, err)
	assert.False(t, shipped, "absent source is not shipped")

	_, shipped, err = idx.Lookup("9999.9", "pkg:deb/debian/glibc")
	require.NoError(t, err)
	assert.False(t, shipped, "absent release is not shipped")
}

// A semver release is keyed by its three-part GL version string.
func TestAccumulator_SemverReleaseKey(t *testing.T) {
	t.Parallel()

	s := shippedversions.NewAccumulator(shippedversions.WithMinPerRelease(1))
	require.NoError(t, s.AddSBOM(gltest.Release(t, "2150.8.1", "kvm"), "kvm", gltest.BOM(
		debComponent("libc6", "glibc", "2.31-13", "", purl.NamespaceDebian, "amd64"),
	)))

	idx, err := s.Result()
	require.NoError(t, err)
	assert.Equal(t, []string{"2150.8.1"}, idx.Releases())

	_, shipped, err := idx.Lookup("2150.8.1", "pkg:deb/debian/glibc")
	require.NoError(t, err)
	assert.True(t, shipped)
}

// Cross-architecture binNMU: the same source at the same source version from two
// binaries collapses to one entry, not an anomaly.
func TestAccumulator_BinNMUCollapsesToOneVersion(t *testing.T) {
	t.Parallel()

	s := shippedversions.NewAccumulator(shippedversions.WithMinPerRelease(1))
	require.NoError(t, s.AddSBOM(gltest.Release(t, "1877.3", "kvm"), "kvm", gltest.BOM(
		debComponent("libc6", "glibc", "2.31-13", "2.31-13", purl.NamespaceDebian, "amd64"),
		debComponent("libc6", "glibc", "2.31-13+b1", "2.31-13", purl.NamespaceDebian, "arm64"),
	)))

	idx, err := s.Result()
	require.NoError(t, err)

	versioned, shipped, err := idx.Lookup("1877.3", "pkg:deb/debian/glibc")
	require.NoError(t, err)
	assert.True(t, shipped)
	assert.Equal(t, "pkg:deb/debian/glibc@2.31-13", versioned)
}

// Two genuinely distinct source versions for one source in a release is a hard error.
func TestAccumulator_MultipleSourceVersionsHardFails(t *testing.T) {
	t.Parallel()

	s := shippedversions.NewAccumulator(shippedversions.WithMinPerRelease(1))
	err := s.AddSBOM(gltest.Release(t, "1877.3", "kvm"), "kvm", gltest.BOM(
		debComponent("libc6", "glibc", "2.31-13", "2.31-13", purl.NamespaceDebian, "amd64"),
		debComponent("libc-bin", "glibc", "2.31-14", "2.31-14", purl.NamespaceDebian, "amd64"),
	))
	require.ErrorIs(t, err, shippedversions.ErrMultipleVersions)
}

func TestAccumulator_FallsBackToInReleaseOnMissingSBOMSet(t *testing.T) {
	t.Parallel()

	inRelPkgs := []packages.Package{
		{
			Name:          "libc6",
			Source:        "glibc",
			Version:       "2.31-13",
			SourceVersion: "2.31-13",
			Namespace:     purl.NamespaceGardenLinux,
		},
		{Name: "bash", Source: "bash", Version: "5.1-2", SourceVersion: "5.1-2", Namespace: purl.NamespaceDebian},
	}

	var gotRelease version.GardenLinuxRelease
	s := shippedversions.NewAccumulator(
		shippedversions.WithMinPerRelease(1),
		shippedversions.WithInReleaseFetch(
			func(_ context.Context, r version.GardenLinuxRelease) ([]packages.Package, error) {
				gotRelease = r

				return inRelPkgs, nil
			}),
	)
	require.NoError(t, s.MissingSBOMSet(t.Context(), gltest.Release(t, "1877.3", "metal-amd64")))

	idx, err := s.Result()
	require.NoError(t, err)

	assert.Equal(t, "1877.3", gotRelease.Name)
	versioned, shipped, err := idx.Lookup("1877.3", "pkg:deb/debian/glibc")
	require.NoError(t, err)
	assert.True(t, shipped)
	assert.Equal(t, "pkg:deb/gardenlinux/glibc@2.31-13", versioned)
}

func TestResult_HardFailsBelowThreshold(t *testing.T) {
	t.Parallel()

	s := shippedversions.NewAccumulator(shippedversions.WithMinPerRelease(100))
	require.NoError(t, s.AddSBOM(gltest.Release(t, "1877.3", "kvm"), "kvm", gltest.BOM(
		debComponent("libc6", "glibc", "2.31-13", "", purl.NamespaceDebian, "amd64"),
	)))

	_, err := s.Result()
	require.ErrorIs(t, err, shippedversions.ErrBelowThreshold)
}

func TestAccumulator_HardFailsOnInReleaseFetchError(t *testing.T) {
	t.Parallel()

	fetchErr := errors.New("storage unreachable")
	s := shippedversions.NewAccumulator(
		shippedversions.WithInReleaseFetch(
			func(_ context.Context, _ version.GardenLinuxRelease) ([]packages.Package, error) {
				return nil, fetchErr
			}),
	)
	err := s.MissingSBOMSet(t.Context(), gltest.Release(t, "1877.3", "metal-amd64"))
	require.ErrorIs(t, err, fetchErr)
}
