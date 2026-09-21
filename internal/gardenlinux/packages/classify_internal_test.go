package packages

// classifyComponents partitions SBOM components so no component is silently
// dropped. The Unknown residual is the coverage-gap signal and is tested
// directly here because it is unreachable through the public deb-only API.

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	packageurl "github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClassifyComponents(t *testing.T) {
	t.Parallel()

	components := []cdx.Component{
		{
			Name:       "libc6",
			Type:       cdx.ComponentTypeLibrary,
			PackageURL: "pkg:deb/debian/libc6@2.31-13?upstream=glibc&arch=amd64",
		},
		{
			Name:       "github.com/bar/baz",
			Type:       cdx.ComponentTypeLibrary,
			PackageURL: "pkg:golang/github.com/bar/baz@v1.0.0",
		},
		{
			Name: "debian",
			Type: cdx.ComponentTypeOS,
		},
		{
			Name: "/usr/bin/foo",
			Type: cdx.ComponentTypeFile,
		},
	}

	c := classifyComponents(components)

	require.Len(t, c.Deb, 1)
	assert.Equal(t, "libc6", c.Deb[0].Component.Name)
	assert.Equal(t, packageurl.TypeDebian, c.Deb[0].PURL.Type)

	require.Len(t, c.NonDeb, 1)
	assert.Equal(t, "github.com/bar/baz", c.NonDeb[0].Component.Name)
	assert.Equal(t, "golang", c.NonDeb[0].PURL.Type)

	require.Len(t, c.Ignored, 2)
	assert.Empty(t, c.Unknown)
}

// A package-like component (library/application/...) with a missing or malformed
// PURL is the residual we must never drop silently: it lands in Unknown so the
// coverage gap surfaces.
func TestClassifyComponentsUnknownResidual(t *testing.T) {
	t.Parallel()

	components := []cdx.Component{
		{
			Name: "mystery-lib",
			Type: cdx.ComponentTypeLibrary,
			// No PackageURL, but a package-type component.
		},
		{
			Name:       "broken-app",
			Type:       cdx.ComponentTypeApplication,
			PackageURL: "not-a-valid-purl",
		},
	}

	c := classifyComponents(components)

	assert.Empty(t, c.Deb)
	assert.Empty(t, c.NonDeb)
	assert.Empty(t, c.Ignored)
	require.Len(t, c.Unknown, 2)
	assert.Equal(t, "mystery-lib", c.Unknown[0].Name)
	assert.Equal(t, "broken-app", c.Unknown[1].Name)
}

// checkComponentCoverage must fail when the Unknown bucket is non-empty, since
// an unclassified component is a potential silent false-negative.
func TestCheckComponentCoverage(t *testing.T) {
	t.Parallel()

	t.Run("empty unknown bucket passes", func(t *testing.T) {
		t.Parallel()

		c := classification{
			Deb:     []classifiedComponent{{}},
			NonDeb:  []classifiedComponent{{}},
			Ignored: []cdx.Component{{}},
		}

		assert.NoError(t, checkComponentCoverage(c))
	})

	t.Run("non-empty unknown bucket fails", func(t *testing.T) {
		t.Parallel()

		c := classification{
			Unknown: []cdx.Component{
				{Name: "mystery-lib"},
				{Name: "broken-app"},
			},
		}

		err := checkComponentCoverage(c)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "mystery-lib")
		assert.Contains(t, err.Error(), "broken-app")
	})
}
