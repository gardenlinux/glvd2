package flavorinventory_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/flavorinventory"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/gltest"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/packages"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/version"
	"github.com/gardenlinux/glvd2/internal/purl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// gldeb builds a "Garden Linux"-namespaced gldeb component from a binary name and source.
func gldeb(name, source string) cdx.Component {
	return gltest.DebComponent(packages.Package{Name: name, Source: source, Namespace: purl.NamespaceGardenLinux})
}

func TestAccumulator_PerFlavorInclusion(t *testing.T) {
	t.Parallel()

	rel := gltest.Release(t, "1877.3", "kvm", "metal")
	s := flavorinventory.NewAccumulator()

	// glibc is universal; openssl ships only in kvm; grub only in metal.
	require.NoError(t, s.AddSBOM(rel, "kvm", gltest.BOM(
		gldeb("libc6", "glibc"),
		gldeb("libssl3", "openssl"),
	)))
	require.NoError(t, s.AddSBOM(rel, "metal", gltest.BOM(
		gldeb("libc6", "glibc"),
		gldeb("grub-common", "grub2"),
	)))

	inv := s.Result()

	flavors, shipped, err := inv.Lookup("1877.3", "pkg:deb/gardenlinux/glibc")
	require.NoError(t, err)
	assert.True(t, shipped)
	assert.Equal(t, []string{"kvm", "metal"}, flavors, "universal source appears under all flavors")

	flavors, shipped, err = inv.Lookup("1877.3", "pkg:deb/gardenlinux/openssl")
	require.NoError(t, err)
	assert.True(t, shipped)
	assert.Equal(t, []string{"kvm"}, flavors, "kvm-only source appears under exactly kvm")

	flavors, shipped, err = inv.Lookup("1877.3", "pkg:deb/gardenlinux/grub2")
	require.NoError(t, err)
	assert.True(t, shipped)
	assert.Equal(t, []string{"metal"}, flavors)
}

func TestLookup_NamespaceVariantTolerant(t *testing.T) {
	t.Parallel()

	s := flavorinventory.NewAccumulator()
	require.NoError(t, s.AddSBOM(gltest.Release(t, "1877.3", "kvm"), "kvm", gltest.BOM(
		gltest.DebComponent(packages.Package{Name: "libc6", Source: "glibc"}),
	)))
	inv := s.Result()

	for _, q := range []string{"pkg:deb/gardenlinux/glibc", "pkg:deb/debian/glibc"} {
		flavors, shipped, err := inv.Lookup("1877.3", q)
		require.NoError(t, err)
		assert.True(t, shipped, "query %q must hit", q)
		assert.Equal(t, []string{"kvm"}, flavors)
	}
}

func TestLookup_NotShipped(t *testing.T) {
	t.Parallel()

	s := flavorinventory.NewAccumulator()
	require.NoError(t, s.AddSBOM(gltest.Release(t, "1877.3", "kvm"), "kvm", gltest.BOM(
		gldeb("libc6", "glibc"),
	)))
	inv := s.Result()

	_, shipped, err := inv.Lookup("1877.3", "pkg:deb/gardenlinux/wayland")
	require.NoError(t, err)
	assert.False(t, shipped, "absent source is not shipped")

	_, shipped, err = inv.Lookup("9999.9", "pkg:deb/gardenlinux/glibc")
	require.NoError(t, err)
	assert.False(t, shipped, "absent release is not shipped")
}

func TestAccumulator_InReleaseFallbackUsesPool(t *testing.T) {
	t.Parallel()

	s := flavorinventory.NewAccumulator(
		flavorinventory.WithInReleaseFetch(
			func(_ context.Context, _ version.GardenLinuxRelease) ([]packages.Package, error) {
				return []packages.Package{
					{Name: "libc6", Source: "glibc", Namespace: purl.NamespaceDebian},
				}, nil
			}),
	)
	require.NoError(t, s.MissingSBOMSet(t.Context(), gltest.Release(t, "2150.8.1", "metal-amd64")))

	inv := s.Result()

	flavors, shipped, err := inv.Lookup("2150.8.1", "pkg:deb/debian/glibc")
	require.NoError(t, err)
	assert.True(t, shipped)
	assert.Equal(t, []string{flavorinventory.PoolFlavor}, flavors, "pre-SBOM release degrades to the pool flavor")
}

func TestAuditEntries_Stable(t *testing.T) {
	t.Parallel()

	// Build the same inventory twice with flavors/components fed in different orders.
	build := func(order int) flavorinventory.Inventory {
		s := flavorinventory.NewAccumulator()
		rel := gltest.Release(t, "1877.3", "kvm", "metal")
		if order == 0 {
			require.NoError(t, s.AddSBOM(rel, "metal", gltest.BOM(
				gldeb("grub-common", "grub2"),
				gldeb("libc6", "glibc"),
			)))
			require.NoError(t, s.AddSBOM(rel, "kvm", gltest.BOM(
				gldeb("libssl3", "openssl"),
				gldeb("libc6", "glibc"),
			)))
		} else {
			require.NoError(t, s.AddSBOM(rel, "kvm", gltest.BOM(
				gldeb("libc6", "glibc"),
				gldeb("libssl3", "openssl"),
			)))
			require.NoError(t, s.AddSBOM(rel, "metal", gltest.BOM(
				gldeb("libc6", "glibc"),
				gldeb("grub-common", "grub2"),
			)))
		}

		return s.Result()
	}

	first, err := json.Marshal(build(0).AuditEntries())
	require.NoError(t, err)
	second, err := json.Marshal(build(1).AuditEntries())
	require.NoError(t, err)

	assert.Equal(t, string(first), string(second), "same input yields identical bytes regardless of feed order")

	// Spot-check the stable, sorted shape.
	entries := build(0).AuditEntries()
	require.Len(t, entries, 1)
	assert.Equal(t, "1877.3", entries[0].Release)
	require.Len(t, entries[0].Flavors, 2)
	assert.Equal(t, "kvm", entries[0].Flavors[0].Flavor)
	assert.Equal(t, "metal", entries[0].Flavors[1].Flavor)
	assert.Equal(t, []string{"pkg:deb/gardenlinux/glibc", "pkg:deb/gardenlinux/openssl"}, entries[0].Flavors[0].Sources)
}

func TestAccumulator_HardFailsOnSBOMConversionError(t *testing.T) {
	t.Parallel()

	components := []cdx.Component{{Type: cdx.ComponentTypeLibrary, Name: "mystery"}}
	s := flavorinventory.NewAccumulator()
	err := s.AddSBOM(gltest.Release(t, "1877.3", "kvm"), "kvm", &cdx.BOM{Components: &components})
	require.Error(t, err)
}

func TestAccumulator_HardFailsOnInReleaseFetchError(t *testing.T) {
	t.Parallel()

	fetchErr := errors.New("storage unreachable")
	s := flavorinventory.NewAccumulator(
		flavorinventory.WithInReleaseFetch(
			func(_ context.Context, _ version.GardenLinuxRelease) ([]packages.Package, error) {
				return nil, fetchErr
			}),
	)
	err := s.MissingSBOMSet(t.Context(), gltest.Release(t, "1877.3", "metal-amd64"))
	require.ErrorIs(t, err, fetchErr)
}
