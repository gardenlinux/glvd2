// Package gltest provides shared test fixtures for Garden Linux packages
package gltest

import (
	"strconv"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/glrd"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/packages"
	"github.com/gardenlinux/glvd2/internal/purl"
	"github.com/stretchr/testify/require"
)

// Release builds a GLRD release from a version string
// like "1877.3" (legacy) or "2150.8.1" (semver) and the given flavors.
func Release(t *testing.T, ver string, flavors ...string) glrd.Release {
	t.Helper()

	const (
		minParts = 2 // major.minor
		maxParts = 3 // major.minor.patch
	)

	parts := strings.Split(ver, ".")
	require.GreaterOrEqual(t, len(parts), minParts, "version needs at least major.minor")
	require.LessOrEqual(t, len(parts), maxParts, "version has at most major.minor.patch")

	nums := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		require.NoErrorf(t, err, "parsing version part %q", p)
		nums[i] = n
	}

	v := glrd.Version{Major: nums[0], Minor: nums[1]}
	if len(parts) == maxParts {
		v.Patch = nums[2]
	}

	return glrd.Release{Name: ver, Version: v, Flavors: flavors}
}

// DebComponent builds a deb component whose PURL encodes name, version,
// namespace, and architecture.
func DebComponent(pkg packages.Package) cdx.Component {
	namespace := pkg.Namespace
	if namespace == "" {
		namespace = purl.NamespaceDebian
	}
	pkgVersion := pkg.Version
	if pkgVersion == "" {
		pkgVersion = "1.0"
	}

	purlStr := "pkg:deb/" + namespace + "/" + pkg.Name + "@" + pkgVersion
	var qualifiers []string
	if pkg.Architecture != "" {
		qualifiers = append(qualifiers, "arch="+pkg.Architecture)
	}
	if pkg.Source != "" && (pkg.Source != pkg.Name || pkg.SourceVersion != "") {
		upstream := pkg.Source
		if pkg.SourceVersion != "" {
			upstream += "@" + pkg.SourceVersion
		}
		qualifiers = append(qualifiers, "upstream="+upstream)
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

// BOM builds a CycloneDX BOM from the given components.
func BOM(components ...cdx.Component) *cdx.BOM {
	return &cdx.BOM{Components: &components}
}

// BOMFromPackages builds a CycloneDX BOM whose deb components round-trip through
// the real conversion back to the given packages.
func BOMFromPackages(pkgs ...packages.Package) *cdx.BOM {
	components := make([]cdx.Component, 0, len(pkgs))
	for _, pkg := range pkgs {
		components = append(components, DebComponent(pkg))
	}

	return &cdx.BOM{Components: &components}
}
