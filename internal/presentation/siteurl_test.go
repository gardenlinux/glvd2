package presentation_test

import (
	"testing"

	"github.com/gardenlinux/glvd2/internal/presentation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSiteURLs_DebianPackageNames(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		valid bool
	}{
		{"glibc", true},
		{"libstdc++6", true},
		{"gtk+3.0", true},
		{"python3.13", true},
		{"0ad", true},
		{"linux-tools", true},
		{"", false},
		{"a", false},
		{"..", false},
		{"../glibc", false},
		{"%2e%2e", false},
		{"bad/name", false},
		{"bad name", false},
		{"bad_name", false},
		{"bad#fragment", false},
		{"bad?query", false},
		{"GLIBC", false},
		{"index.html", false},
		{"-glibc", false},
	}

	s := presentation.SiteURLs{}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			path, err := s.Package(tc.name)
			if !tc.valid {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)

			assert.Equal(t, "packages/"+tc.name+"/index.html", path)
		})
	}
}

func TestSiteURLs_ArtifactPaths(t *testing.T) {
	t.Parallel()

	s := presentation.SiteURLs{}

	assert.Equal(t, "index.html", s.Root())
	assert.Equal(t, "cves/index.html", s.CVEs())
	assert.Equal(t, "statistics/index.html", s.Statistics())
	assert.Equal(t, "packages/index.html", s.Packages())

	pkg, err := s.Package("glibc")
	require.NoError(t, err)
	assert.Equal(t, "packages/glibc/index.html", pkg)

	release, err := s.Release("1877.26")
	require.NoError(t, err)
	assert.Equal(t, "releases/1877.26/index.html", release)

	flavor, err := s.Flavor("1877.26", "aws")
	require.NoError(t, err)
	assert.Equal(t, "releases/1877.26/flavors/aws/index.html", flavor)

	cve, err := s.CVE("CVE-2024-0001")
	require.NoError(t, err)
	assert.Equal(t, "cves/CVE-2024-0001/index.html", cve)
}

func TestSiteURLs_RejectsUnsafeSegments(t *testing.T) {
	t.Parallel()

	s := presentation.SiteURLs{}
	cases := []string{"", ".", "..", "../etc", "2024/evil", "bad\\path", "bad\x00name", "bad#fragment", "bad?query"}
	for _, value := range cases {
		t.Run(value, func(t *testing.T) {
			t.Parallel()

			_, err := s.Release(value)
			require.Error(t, err)

			_, err = s.Flavor(value, "aws")
			require.Error(t, err)

			_, err = s.Flavor("1877.26", value)
			require.Error(t, err)

			_, err = s.CVE(value)
			require.Error(t, err)

			_, err = s.Package(value)
			require.Error(t, err)
		})
	}
}
