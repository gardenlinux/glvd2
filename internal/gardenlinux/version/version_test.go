package version_test

import (
	"testing"

	"github.com/gardenlinux/glvd2/internal/gardenlinux/glrd"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/version"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMakeGardenLinuxReleaseFromString_Valid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want version.GardenLinuxRelease
	}{
		{
			name: "legacy two-part",
			in:   "1.2",
			want: version.GardenLinuxRelease{Name: "1.2", Major: 1, Minor: 2, Patch: 0, SemVer: false},
		},
		{
			name: "legacy just below threshold",
			in:   "2016.0",
			want: version.GardenLinuxRelease{Name: "2016.0", Major: 2016, Minor: 0, Patch: 0, SemVer: false},
		},
		{
			name: "legacy minor greater than zero",
			in:   "1877.14",
			want: version.GardenLinuxRelease{Name: "1877.14", Major: 1877, Minor: 14, Patch: 0, SemVer: false},
		},
		{
			name: "semver at threshold",
			in:   "2017.0.0",
			want: version.GardenLinuxRelease{Name: "2017.0.0", Major: 2017, Minor: 0, Patch: 0, SemVer: true},
		},
		{
			name: "semver all non-zero parts",
			in:   "2150.1.2",
			want: version.GardenLinuxRelease{Name: "2150.1.2", Major: 2150, Minor: 1, Patch: 2, SemVer: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := version.MakeGardenLinuxReleaseFromString(tt.in)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
			// Format is derived from SemVer, so the round-trip must reproduce the input.
			assert.Equal(t, tt.in, got.Format())
		})
	}
}

func TestMakeGardenLinuxReleaseFromString_Errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		// wantMsg is the exact error message when the parser returns a defined
		// sentinel string. Left empty for cases that surface a strconv error.
		wantMsg string
	}{
		{
			name:    "three parts below threshold",
			in:      "1.2.3",
			wantMsg: "prior semver version expects only two version parts",
		},
		{
			name:    "three parts just below threshold",
			in:      "2016.0.0",
			wantMsg: "prior semver version expects only two version parts",
		},
		{
			name:    "two parts at threshold",
			in:      "2017.0",
			wantMsg: "semver version schema expects three version parts",
		},
		{
			name:    "too many parts",
			in:      "1.2.3.4.5.6",
			wantMsg: "invalid version schema",
		},
		{
			name:    "single part",
			in:      "1",
			wantMsg: "invalid version schema",
		},
		{
			name:    "empty string",
			in:      "",
			wantMsg: "invalid version schema",
		},
		{
			name: "trailing separator",
			in:   "1.",
		},
		{
			name: "non-numeric parts",
			in:   "a.b",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := version.MakeGardenLinuxReleaseFromString(tt.in)
			require.Error(t, err)
			if tt.wantMsg != "" {
				assert.Equal(t, tt.wantMsg, err.Error())
			}
		})
	}
}

func TestMakeGardenLinuxRelease(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   glrd.Version
		want version.GardenLinuxRelease
	}{
		{
			name: "legacy two-part",
			in:   glrd.Version{Major: 1877, Minor: 0},
			want: version.GardenLinuxRelease{Name: "1877.0", Major: 1877, Minor: 0, Patch: 0, SemVer: false},
		},
		{
			name: "legacy two-part (minor > 0)",
			in:   glrd.Version{Major: 1877, Minor: 4},
			want: version.GardenLinuxRelease{Name: "1877.4", Major: 1877, Minor: 4, Patch: 0, SemVer: false},
		},
		{
			name: "legacy just below threshold",
			in:   glrd.Version{Major: version.SemverMajorThreshold - 1, Minor: 0},
			want: version.GardenLinuxRelease{Name: "2016.0", Major: 2016, Minor: 0, Patch: 0, SemVer: false},
		},
		{
			name: "semver at threshold",
			in:   glrd.Version{Major: version.SemverMajorThreshold, Minor: 0, Patch: 0},
			want: version.GardenLinuxRelease{Name: "2017.0.0", Major: 2017, Minor: 0, Patch: 0, SemVer: true},
		},
		{
			name: "semver minor and patch zero",
			in:   glrd.Version{Major: 2150, Minor: 0, Patch: 0},
			want: version.GardenLinuxRelease{Name: "2150.0.0", Major: 2150, Minor: 0, Patch: 0, SemVer: true},
		},
		{
			name: "semver all non-zero parts",
			in:   glrd.Version{Major: 2150, Minor: 8, Patch: 1},
			want: version.GardenLinuxRelease{Name: "2150.8.1", Major: 2150, Minor: 8, Patch: 1, SemVer: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, version.MakeGardenLinuxRelease(tt.in))
		})
	}
}

func TestFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   version.GardenLinuxRelease
		want string
	}{
		{
			name: "semver uses three parts",
			in:   version.GardenLinuxRelease{Major: 2150, Minor: 1, Patch: 2, SemVer: true},
			want: "2150.1.2",
		},
		{
			name: "legacy uses two parts",
			in:   version.GardenLinuxRelease{Major: 1877, Minor: 14, Patch: 0, SemVer: false},
			want: "1877.14",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, tt.in.Format())
		})
	}
}
