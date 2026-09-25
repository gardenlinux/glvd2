package vendormap_test

import (
	"context"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/glrd"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/vendormap"
	"github.com/gardenlinux/glvd2/internal/ingestion/cvelistv5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func release(name string) glrd.Release {
	return glrd.Release{Name: name, Version: glrd.Version{Major: 1877, Minor: 0}}
}

// bomDebVendorsGolang builds a CycloneDX BOM where a deb source vendors a golang module.
func bomDebVendorsGolang(debSource, debPURL, goPURL string) *cdx.BOM {
	components := []cdx.Component{
		{BOMRef: "deb", Type: cdx.ComponentTypeLibrary, Name: debSource, Version: "1.0", PackageURL: debPURL},
		{BOMRef: "go", Type: cdx.ComponentTypeLibrary, Name: "mod", Version: "v1.0.0", PackageURL: goPURL},
	}
	deps := []cdx.Dependency{{Ref: "deb", Dependencies: &[]string{"go"}}}

	return &cdx.BOM{Components: &components, Dependencies: &deps}
}

func idsFromPURL(purl string) cvelistv5.Identifiers {
	return cvelistv5.Identifiers{PackageURLs: []string{purl}}
}

func TestAccumulator_ResolvesVendoredGolangToDebSource(t *testing.T) {
	t.Parallel()

	s := vendormap.NewAccumulator()
	require.NoError(t, s.AddSBOM(bomDebVendorsGolang("containerd",
		"pkg:deb/debian/containerd@1.0?arch=amd64", "pkg:golang/golang.org/x/net@v0.23.0")))

	rules, err := s.Result()
	require.NoError(t, err)

	assert.Equal(t, []string{"pkg:deb/debian/containerd"},
		rules.Lookup(idsFromPURL("pkg:golang/golang.org/x/net@v0.23.0")))
	assert.Nil(t, rules.Lookup(idsFromPURL("pkg:golang/github.com/unrelated/x@v1.0.0")))
}

// The same vendored dep across two releases collapses to one target.
func TestAccumulator_UnionsSameDepAcrossReleases(t *testing.T) {
	t.Parallel()

	s := vendormap.NewAccumulator()
	for range 2 {
		require.NoError(t, s.AddSBOM(bomDebVendorsGolang("containerd",
			"pkg:deb/debian/containerd@1.0?arch=amd64", "pkg:golang/golang.org/x/net@v0.23.0")))
	}

	rules, err := s.Result()
	require.NoError(t, err)

	assert.Equal(t, []string{"pkg:deb/debian/containerd"},
		rules.Lookup(idsFromPURL("pkg:golang/golang.org/x/net@v0.23.0")))
}

// A dep vendored by two different packages yields both targets (set-valued).
func TestAccumulator_SameDepTwoPackagesYieldsBothTargets(t *testing.T) {
	t.Parallel()

	goPURL := "pkg:golang/github.com/shared/mod@v1.0.0"

	s := vendormap.NewAccumulator()
	require.NoError(t, s.AddSBOM(bomDebVendorsGolang("pkga", "pkg:deb/debian/pkga@1.0?arch=amd64", goPURL)))
	require.NoError(t, s.AddSBOM(bomDebVendorsGolang("pkgb", "pkg:deb/debian/pkgb@1.0?arch=amd64", goPURL)))

	rules, err := s.Result()
	require.NoError(t, err)

	assert.Equal(t, []string{"pkg:deb/debian/pkga", "pkg:deb/debian/pkgb"},
		rules.Lookup(idsFromPURL(goPURL)))
}

// MissingSBOMSet is ignored: without an SBOM there is no dependency graph.
func TestAccumulator_MissingSBOMSetContributesNothing(t *testing.T) {
	t.Parallel()

	s := vendormap.NewAccumulator()
	require.NoError(t, s.MissingSBOMSet(context.Background(), release("r")))

	rules, err := s.Result()
	require.NoError(t, err)
	assert.Nil(t, rules.Lookup(idsFromPURL("pkg:golang/github.com/any/mod@v1.0.0")))
}
