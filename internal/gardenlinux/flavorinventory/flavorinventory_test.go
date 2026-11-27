package flavorinventory_test

import (
	"encoding/json"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/flavorinventory"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/gltest"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/packages"
	"github.com/gardenlinux/glvd2/internal/purl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// gldeb builds a "Garden Linux"-namespaced deb component from a binary name and source.
func gldeb(name, source string) cdx.Component {
	return gltest.DebComponent(packages.Package{Name: name, Source: source, Namespace: purl.NamespaceGardenLinux})
}

func TestRecord_PerFlavorSBOMs(t *testing.T) {
	t.Parallel()

	rel := "1877.3"
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

	rec := s.Result().Record()

	require.Len(t, rec.Releases, 1)
	assert.Equal(t, rel, rec.Releases[0].Release)
	assert.Equal(t, map[string][]string{
		"kvm":   {"pkg:deb/gardenlinux/glibc", "pkg:deb/gardenlinux/openssl"},
		"metal": {"pkg:deb/gardenlinux/glibc", "pkg:deb/gardenlinux/grub2"},
	}, rec.Releases[0].Flavors)
}

func TestRecord_IncompleteSBOMSetRecordsNoRelease(t *testing.T) {
	t.Parallel()

	s := flavorinventory.NewAccumulator()
	require.NoError(t, s.MissingSBOMSet(t.Context(), "2150.8.1"))

	rec := s.Result().Record()

	assert.Empty(t, rec.Releases, "an incomplete SBOM set records no flavor membership")
}

func TestRecord_NumericReleaseOrdering(t *testing.T) {
	t.Parallel()

	s := flavorinventory.NewAccumulator()
	// Lexical order would put "1000.1" before "184.1" before "99.1"; numeric order differs.
	for _, rel := range []string{"1000.1", "99.1", "184.1"} {
		require.NoError(t, s.AddSBOM(rel, "kvm", gltest.BOM(gldeb("libc6", "glibc"))))
	}

	rec := s.Result().Record()

	got := make([]string, len(rec.Releases))
	for i, r := range rec.Releases {
		got[i] = r.Release
	}
	assert.Equal(t, []string{"99.1", "184.1", "1000.1"}, got)
}

// TestRecord_StableAcrossArrivalOrder verifies identical input in different arrival orders
// serializes to identical bytes.
func TestRecord_StableAcrossArrivalOrder(t *testing.T) {
	t.Parallel()

	build := func(order int) flavorinventory.Inventory {
		s := flavorinventory.NewAccumulator()
		rel := "1877.3"
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

	first, err := json.Marshal(build(0).Record())
	require.NoError(t, err)
	second, err := json.Marshal(build(1).Record())
	require.NoError(t, err)

	assert.Equal(t, string(first), string(second), "same input yields identical bytes regardless of feed order")
}

func TestAccumulator_HardFailsOnSBOMConversionError(t *testing.T) {
	t.Parallel()

	components := []cdx.Component{{Type: cdx.ComponentTypeLibrary, Name: "mystery"}}
	s := flavorinventory.NewAccumulator()
	err := s.AddSBOM("1877.3", "kvm", &cdx.BOM{Components: &components})
	require.Error(t, err)
}

func TestInventory_Accessors(t *testing.T) {
	t.Parallel()

	s := flavorinventory.NewAccumulator()
	require.NoError(t, s.AddSBOM("1877.3", "zlast", gltest.BOM(gldeb("libc6", "glibc"))))
	require.NoError(t, s.AddSBOM("1877.3", "metal", gltest.BOM(gldeb("libc6", "glibc"))))
	require.NoError(t, s.AddSBOM("1877.3", "kvm", gltest.BOM(
		gldeb("libc6", "glibc"),
		gldeb("libssl3", "openssl"),
	)))
	inv := s.Result()

	assert.True(t, inv.HasFlavors("1877.3"))
	assert.False(t, inv.HasFlavors("9999.0"))
	assert.Equal(t, []string{"1877.3"}, inv.Releases())
	assert.Equal(t, []string{"kvm", "metal", "zlast"}, inv.Flavors("1877.3"), "flavors are sorted")
	assert.Nil(t, inv.Flavors("9999.0"))
}

func TestInventory_ContainsIsNamespaceTolerant(t *testing.T) {
	t.Parallel()

	s := flavorinventory.NewAccumulator()
	require.NoError(t, s.AddSBOM("1877.3", "kvm", gltest.BOM(gldeb("libssl3", "openssl"))))
	inv := s.Result()

	// Membership stores the gardenlinux namespace; the debian variant still matches.
	found, err := inv.Contains("1877.3", "kvm", "pkg:deb/debian/openssl")
	require.NoError(t, err)
	assert.True(t, found)

	absent, err := inv.Contains("1877.3", "kvm", "pkg:deb/gardenlinux/glibc")
	require.NoError(t, err)
	assert.False(t, absent)

	// A release or flavor that is not covered contains nothing.
	missing, err := inv.Contains("9999.0", "kvm", "pkg:deb/gardenlinux/openssl")
	require.NoError(t, err)
	assert.False(t, missing)
}
