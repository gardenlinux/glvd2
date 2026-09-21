package packages

// extractSource is unexported and its resolution order is not reachable through
// the public API without a full SBOM fixture, so it is tested directly here.

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	packageurl "github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractSource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		purl       string
		properties []cdx.Property
		want       string
		wantErr    bool
	}{
		{
			name: "upstream qualifier with version",
			purl: "pkg:deb/debian/libc6@2.31-13?upstream=glibc@2.31-13&arch=amd64",
			want: "glibc",
		},
		{
			name: "upstream qualifier without version",
			purl: "pkg:deb/debian/libc6@2.31-13?upstream=glibc&arch=amd64",
			want: "glibc",
		},
		{
			name:       "syft metadata source property",
			purl:       "pkg:deb/debian/libc6@2.31-13?arch=amd64",
			properties: []cdx.Property{{Name: "syft:metadata:source", Value: "glibc"}},
			want:       "glibc",
		},
		{
			name: "upstream qualifier beats property",
			purl: "pkg:deb/debian/libc6@2.31-13?upstream=glibc&arch=amd64",
			properties: []cdx.Property{
				{Name: "syft:metadata:source", Value: "wrong"},
			},
			want: "glibc",
		},
		{
			name: "binary-name fallback when no upstream or property",
			purl: "pkg:deb/debian/openssl@3.0.11-1?arch=amd64",
			want: "openssl",
		},
		{
			name:       "binary-name fallback when property empty",
			purl:       "pkg:deb/debian/openssl@3.0.11-1?arch=amd64",
			properties: []cdx.Property{{Name: "syft:metadata:source", Value: ""}},
			want:       "openssl",
		},
		{
			name:    "upstream qualifier with only version is invalid",
			purl:    "pkg:deb/debian/libc6@2.31-13?upstream=@2.31-13&arch=amd64",
			wantErr: true,
		},
		{
			name:       "invalid source name in property",
			purl:       "pkg:deb/debian/libc6@2.31-13?arch=amd64",
			properties: []cdx.Property{{Name: "syft:metadata:source", Value: "Bad_Name"}},
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pkgurl, err := packageurl.FromString(tt.purl)
			require.NoError(t, err)

			component := cdx.Component{Name: pkgurl.Name}
			if tt.properties != nil {
				component.Properties = &tt.properties
			}

			got, err := extractSource(component, pkgurl)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestConvertSBOMToPackageListSource(t *testing.T) {
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

	pkgs, err := convertSBOMToPackageList(bom)
	require.NoError(t, err)
	require.Len(t, pkgs, 2)

	assert.Equal(t, "libc6", pkgs[0].Name)
	assert.Equal(t, "glibc", pkgs[0].Source)
	assert.Equal(t, "libsystemd0", pkgs[1].Name)
	assert.Equal(t, "systemd", pkgs[1].Source)
}

// Non-deb components (e.g. vendored pkg:golang dependencies) are skipped rather
// than transformed into fake deb packages.
func TestConvertSBOMToPackageListSkipsNonDeb(t *testing.T) {
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

	pkgs, err := convertSBOMToPackageList(bom)
	require.NoError(t, err)
	require.Len(t, pkgs, 1)
	assert.Equal(t, "foo", pkgs[0].Name)
	assert.Equal(t, "foo", pkgs[0].Source)
}
