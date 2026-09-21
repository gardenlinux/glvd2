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
