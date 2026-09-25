package packages_test

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/packages"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// debComponentWithProps builds a single deb component, optionally carrying syft-style properties.
func debComponentWithProps(name, version, purl string, props []cdx.Property) cdx.Component {
	c := cdx.Component{
		Type:       cdx.ComponentTypeLibrary,
		Name:       name,
		Version:    version,
		PackageURL: purl,
	}
	if props != nil {
		c.Properties = &props
	}

	return c
}

// TestPackageListFromSBOMSource exercises source-package resolution through the public API:
// the upstream qualifier, the syft metadata property, and the binary-name fallback, plus their invalid variants.
func TestPackageListFromSBOMSource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		pkgName    string
		version    string
		purl       string
		properties []cdx.Property
		want       string
		wantErr    bool
	}{
		{
			name:    "upstream qualifier with version",
			pkgName: "libc6",
			version: "2.31-13",
			purl:    "pkg:deb/debian/libc6@2.31-13?upstream=glibc@2.31-13&arch=amd64",
			want:    "glibc",
		},
		{
			name:    "upstream qualifier without version",
			pkgName: "libc6",
			version: "2.31-13",
			purl:    "pkg:deb/debian/libc6@2.31-13?upstream=glibc&arch=amd64",
			want:    "glibc",
		},
		{
			name:       "syft metadata source property",
			pkgName:    "libc6",
			version:    "2.31-13",
			purl:       "pkg:deb/debian/libc6@2.31-13?arch=amd64",
			properties: []cdx.Property{{Name: "syft:metadata:source", Value: "glibc"}},
			want:       "glibc",
		},
		{
			name:    "upstream qualifier beats property",
			pkgName: "libc6",
			version: "2.31-13",
			purl:    "pkg:deb/debian/libc6@2.31-13?upstream=glibc&arch=amd64",
			properties: []cdx.Property{
				{Name: "syft:metadata:source", Value: "wrong"},
			},
			want: "glibc",
		},
		{
			name:    "binary-name fallback when no upstream or property",
			pkgName: "openssl",
			version: "3.0.11-1",
			purl:    "pkg:deb/debian/openssl@3.0.11-1?arch=amd64",
			want:    "openssl",
		},
		{
			name:       "binary-name fallback when property empty",
			pkgName:    "openssl",
			version:    "3.0.11-1",
			purl:       "pkg:deb/debian/openssl@3.0.11-1?arch=amd64",
			properties: []cdx.Property{{Name: "syft:metadata:source", Value: ""}},
			want:       "openssl",
		},
		{
			name:    "upstream qualifier with only version is invalid",
			pkgName: "libc6",
			version: "2.31-13",
			purl:    "pkg:deb/debian/libc6@2.31-13?upstream=@2.31-13&arch=amd64",
			wantErr: true,
		},
		{
			name:       "invalid source name in property",
			pkgName:    "libc6",
			version:    "2.31-13",
			purl:       "pkg:deb/debian/libc6@2.31-13?arch=amd64",
			properties: []cdx.Property{{Name: "syft:metadata:source", Value: "Bad_Name"}},
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			bom := &cdx.BOM{
				Components: &[]cdx.Component{
					debComponentWithProps(tt.pkgName, tt.version, tt.purl, tt.properties),
				},
			}

			pkgs, err := packages.PackageListFromSBOM(bom)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, pkgs, 1)
			assert.Equal(t, tt.want, pkgs[0].Source)
		})
	}
}

func TestPackageListFromSBOMMultipleComponents(t *testing.T) {
	t.Parallel()

	properties := []cdx.Property{{Name: "syft:metadata:source", Value: "systemd"}}
	bom := &cdx.BOM{
		Components: &[]cdx.Component{
			{
				Name:       "libc6",
				Version:    "2.31-13",
				PackageURL: "pkg:deb/debian/libc6@2.31-13?upstream=glibc@2.31-13&arch=amd64",
			},
			{
				Name:       "libsystemd0",
				Version:    "247.3-7",
				PackageURL: "pkg:deb/debian/libsystemd0@247.3-7?arch=amd64",
				Properties: &properties,
			},
		},
	}

	pkgs, err := packages.PackageListFromSBOM(bom)
	require.NoError(t, err)
	require.Len(t, pkgs, 2)
	assert.Equal(t, "libc6", pkgs[0].Name)
	assert.Equal(t, "glibc", pkgs[0].Source)
	assert.Equal(t, "libsystemd0", pkgs[1].Name)
	assert.Equal(t, "systemd", pkgs[1].Source)
}

// Non-deb components (e.g. vendored pkg:golang dependencies) are skipped
// rather than transformed into fake deb packages.
func TestPackageListFromSBOMSkipsNonDeb(t *testing.T) {
	t.Parallel()

	bom := &cdx.BOM{
		Components: &[]cdx.Component{
			{
				Name:       "foo",
				Version:    "1.2.3",
				PackageURL: "pkg:deb/gardenlinux/foo@1.2.3?arch=amd64",
			},
			{
				Name:       "github.com/bar/baz",
				Version:    "v1.0.0",
				PackageURL: "pkg:golang/github.com/bar/baz@v1.0.0",
			},
		},
	}

	pkgs, err := packages.PackageListFromSBOM(bom)
	require.NoError(t, err)
	require.Len(t, pkgs, 1)
	assert.Equal(t, "foo", pkgs[0].Name)
	assert.Equal(t, "foo", pkgs[0].Source)
}
