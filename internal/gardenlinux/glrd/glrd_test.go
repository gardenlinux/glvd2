package glrd_test

import (
	"testing"
	"time"

	"github.com/gardenlinux/glvd2/internal/gardenlinux/glrd"
	"github.com/stretchr/testify/assert"
)

func releaseWithEOL(name string, eol int64) glrd.Release {
	return glrd.Release{
		Name:      name,
		LifeCycle: glrd.LifeCycle{EOL: glrd.LifecycleDate{Timestamp: eol}},
	}
}

func TestIsMaintainedAt(t *testing.T) {
	t.Parallel()

	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	futureSec := now.Add(24 * time.Hour).Unix()
	pastSec := now.Add(-24 * time.Hour).Unix()

	tests := []struct {
		name string
		eol  int64
		want bool
	}{
		{name: "no EOL set is maintained", eol: 0, want: true},
		{name: "EOL in the future is maintained", eol: futureSec, want: true},
		{name: "EOL in the past is not maintained", eol: pastSec, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := releaseWithEOL(tc.name, tc.eol).IsMaintainedAt(now)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestReleasesMaintainedAt(t *testing.T) {
	t.Parallel()

	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	futureSec := now.Add(24 * time.Hour).Unix()
	pastSec := now.Add(-24 * time.Hour).Unix()

	releases := []glrd.Release{
		releaseWithEOL("eol-1", pastSec),
		releaseWithEOL("maintained-1", futureSec),
		releaseWithEOL("maintained-2", futureSec),
		releaseWithEOL("eol-2", pastSec),
		releaseWithEOL("maintained-3", futureSec),
		releaseWithEOL("no-eol", 0),
		releaseWithEOL("maintained-4", futureSec),
	}

	got := glrd.ReleasesMaintainedAt(releases, now)

	names := make([]string, 0, len(got))
	for _, r := range got {
		names = append(names, r.Name)
	}
	assert.Equal(t, []string{"maintained-1", "maintained-2", "maintained-3", "no-eol", "maintained-4"}, names)
}

func TestVersionString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   glrd.Version
		want string
	}{
		{"legacy two parts", glrd.Version{Major: 1877, Minor: 14}, "1877.14"},
		{"legacy ignores patch", glrd.Version{Major: 1877, Minor: 14, Patch: 3}, "1877.14"},
		{"semver three parts", glrd.Version{Major: 2150, Minor: 1, Patch: 2}, "2150.1.2"},
		{"semver threshold", glrd.Version{Major: 2017, Minor: 0, Patch: 0}, "2017.0.0"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, tc.in.String())
		})
	}
}

func TestValidateVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"legacy", "1877.14", false},
		{"semver", "2150.1.2", false},
		{"empty", "", true},
		{"single part", "1877", true},
		{"four parts", "1.2.3.4", true},
		{"non-numeric", "1877.x", true},
		{"minor-prefix", "minor-1877.14", true},
		{"trailing dot", "1877.14.", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := glrd.ValidateVersion(tc.in)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
