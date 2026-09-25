package packages_test

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/packages"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bomWith assembles a BOM from components and dependency edges.
func bomWith(components []cdx.Component, deps []cdx.Dependency) *cdx.BOM {
	return &cdx.BOM{Components: &components, Dependencies: &deps}
}

func debComponent(ref, name, version, purl string) cdx.Component {
	return cdx.Component{
		BOMRef:     ref,
		Type:       cdx.ComponentTypeLibrary,
		Name:       name,
		Version:    version,
		PackageURL: purl,
	}
}

func golangComponent(ref, name, version, purl, cpe string) cdx.Component {
	return cdx.Component{
		BOMRef:     ref,
		Type:       cdx.ComponentTypeLibrary,
		Name:       name,
		Version:    version,
		PackageURL: purl,
		CPE:        cpe,
	}
}

func TestVendored_DebVendorsGolang(t *testing.T) {
	t.Parallel()

	bom := bomWith(
		[]cdx.Component{
			debComponent("deb-ref", "containerd", "1.6.20~ds1-1", "pkg:deb/debian/containerd@1.6.20~ds1-1?arch=amd64"),
			golangComponent("go-ref", "golang.org/x/net", "v0.7.0",
				"pkg:golang/golang.org/x/net@v0.7.0",
				"cpe:2.3:a:golang:net:v0.7.0:*:*:*:*:*:*:*"),
		},
		[]cdx.Dependency{
			{Ref: "deb-ref", Dependencies: &[]string{"go-ref"}},
		},
	)

	groups, err := packages.VendoredFromSBOM(bom)
	require.NoError(t, err)
	require.Len(t, groups, 1)

	group := groups[0]
	assert.Equal(t, "containerd", group.Target.Source)
	assert.Equal(t, "debian", group.Target.Namespace)
	assert.Equal(t, []packages.VendoredComponent{{
		PURL: "pkg:golang/golang.org/x/net@v0.7.0",
		CPE:  "cpe:2.3:a:golang:net:v0.7.0:*:*:*:*:*:*:*",
	}}, group.Children)
}

func TestVendored_DebVendorsGolangWithoutCPE(t *testing.T) {
	t.Parallel()

	bom := bomWith(
		[]cdx.Component{
			debComponent("deb-ref", "containerd", "1.6.20~ds1-1", "pkg:deb/debian/containerd@1.6.20~ds1-1?arch=amd64"),
			golangComponent("go-ref", "golang.org/x/net", "v0.7.0",
				"pkg:golang/golang.org/x/net@v0.7.0", ""),
		},
		[]cdx.Dependency{
			{Ref: "deb-ref", Dependencies: &[]string{"go-ref"}},
		},
	)

	groups, err := packages.VendoredFromSBOM(bom)
	require.NoError(t, err)
	require.Len(t, groups, 1)
	require.Len(t, groups[0].Children, 1)
	assert.Empty(t, groups[0].Children[0].CPE)
	assert.Equal(t, "pkg:golang/golang.org/x/net@v0.7.0", groups[0].Children[0].PURL)
}

func TestVendored_NonVendoredNonDeb(t *testing.T) {
	t.Parallel()

	// A golang component with no deb parent yields no group.
	bom := bomWith(
		[]cdx.Component{
			golangComponent("go-ref", "github.com/lonely/module", "v1.0.0",
				"pkg:golang/github.com/lonely/module@v1.0.0", ""),
		},
		[]cdx.Dependency{
			{Ref: "go-ref", Dependencies: &[]string{}},
		},
	)

	groups, err := packages.VendoredFromSBOM(bom)
	require.NoError(t, err)
	assert.Empty(t, groups)
}

func TestVendored_DebDependingOnDebYieldsNoGroup(t *testing.T) {
	t.Parallel()

	// A deb depending on another deb is not a vendored inclusion.
	bom := bomWith(
		[]cdx.Component{
			debComponent("a", "liba", "1.0", "pkg:deb/debian/liba@1.0?arch=amd64"),
			debComponent("b", "libb", "2.0", "pkg:deb/debian/libb@2.0?arch=amd64"),
		},
		[]cdx.Dependency{
			{Ref: "a", Dependencies: &[]string{"b"}},
		},
	)

	groups, err := packages.VendoredFromSBOM(bom)
	require.NoError(t, err)
	assert.Empty(t, groups)
}

func TestVendored_NoDependencies(t *testing.T) {
	t.Parallel()

	groups, err := packages.VendoredFromSBOM(&cdx.BOM{})
	require.NoError(t, err)
	assert.Nil(t, groups)
}
