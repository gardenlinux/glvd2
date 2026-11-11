package sbom_test

import (
	"testing"

	"github.com/gardenlinux/glvd2/internal/gardenlinux/glrd"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildSBOMURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		release glrd.Release
		flavor  string
		want    string
	}{
		{
			name: "semver release",
			release: glrd.Release{
				Version: glrd.Version{Major: 2150, Minor: 14, Patch: 0},
				Git:     glrd.Git{CommitShort: "a213f775"},
			},
			flavor: "gcp-gardener_prod-arm64",
			want: "https://github.com/gardenlinux/gardenlinux/releases/download/2150.14.0/" +
				"gcp-gardener_prod-arm64-2150.14.0-a213f775.sbom",
		},
		{
			name: "legacy two-part release",
			release: glrd.Release{
				Version: glrd.Version{Major: 1877, Minor: 25},
				Git:     glrd.Git{CommitShort: "abcdefgh"},
			},
			flavor: "kvm",
			want:   "https://github.com/gardenlinux/gardenlinux/releases/download/1877.25/kvm-1877.25-abcdefgh.sbom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := sbom.BuildSBOMURL(tt.release, tt.flavor)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got.String())
		})
	}
}
