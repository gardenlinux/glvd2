package pkgbuild_test

import (
	"testing"

	"github.com/gardenlinux/glvd2/internal/config"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/pkgbuild"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newStore(t *testing.T) *pkgbuild.Store {
	t.Helper()

	return pkgbuild.NewStore(&config.AppConfig{PkgBuildStoreDir: t.TempDir()})
}

func TestStore_SaveAndLookup(t *testing.T) {
	t.Parallel()

	s := newStore(t)
	a := pkgbuild.Analysis{
		PkgName:    "openssl",
		Version:    "3.5.5-1gl1",
		PURL:       "pkg:deb/gardenlinux/openssl",
		Provenance: pkgbuild.ProvenancePatchedFromDebian,
		FixedCVEs:  []pkgbuild.FixedCVE{{ID: "CVE-2024-1234", Kind: "patch-filename"}},
	}
	require.NoError(t, s.Save(a))

	got, err := s.Lookup("openssl", "3.5.5-1gl1")
	require.NoError(t, err)
	assert.Equal(t, a, got)
}

func TestStore_LookupMissing(t *testing.T) {
	t.Parallel()

	_, err := newStore(t).Lookup("absent", "1-1")
	require.ErrorIs(t, err, pkgbuild.ErrNotFound)
}

func TestStore_EntryIsImmutable(t *testing.T) {
	t.Parallel()

	s := newStore(t)
	first := pkgbuild.Analysis{
		PkgName:    "openssl",
		Version:    "1-1gl1",
		PURL:       "pkg:deb/gardenlinux/openssl",
		Provenance: pkgbuild.ProvenanceTakenFromTesting,
	}
	require.NoError(t, s.Save(first))

	// A second save for the same version is rejected and leaves the frozen entry intact.
	err := s.Save(pkgbuild.Analysis{
		PkgName:    "openssl",
		Version:    "1-1gl1",
		PURL:       "pkg:deb/gardenlinux/openssl",
		Provenance: pkgbuild.ProvenanceBuiltFromUpstream,
	})
	require.ErrorIs(t, err, pkgbuild.ErrAlreadyStored)

	got, err := s.Lookup("openssl", "1-1gl1")
	require.NoError(t, err)
	assert.Equal(t, pkgbuild.ProvenanceTakenFromTesting, got.Provenance)
}

func TestStore_BinNMULookupHitsBaseEntry(t *testing.T) {
	t.Parallel()

	s := newStore(t)
	require.NoError(t, s.Save(pkgbuild.Analysis{
		PkgName:    "glibc",
		Version:    "2.31-13",
		PURL:       "pkg:deb/gardenlinux/glibc",
		Provenance: pkgbuild.ProvenanceTakenFromTesting,
	}))

	got, err := s.Lookup("glibc", "2.31-13+b1")
	require.NoError(t, err)
	assert.Equal(t, "2.31-13", got.Version)
}

func TestStore_LookupByPURL_NamespaceAgnostic(t *testing.T) {
	t.Parallel()

	s := newStore(t)
	require.NoError(t, s.Save(pkgbuild.Analysis{
		PkgName:    "openssl",
		Version:    "3.5.5-1gl1",
		PURL:       "pkg:deb/gardenlinux/openssl",
		Provenance: pkgbuild.ProvenancePatchedFromDebian,
	}))

	for _, raw := range []string{
		"pkg:deb/gardenlinux/openssl@3.5.5-1gl1",
		"pkg:deb/debian/openssl@3.5.5-1gl1",
	} {
		got, err := s.LookupByPURL(raw)
		require.NoError(t, err, raw)
		assert.Equal(t, pkgbuild.ProvenancePatchedFromDebian, got.Provenance)
	}
}

func TestStore_LookupByPURL_RequiresVersion(t *testing.T) {
	t.Parallel()

	_, err := newStore(t).LookupByPURL("pkg:deb/gardenlinux/openssl")
	require.Error(t, err)
}

func TestStore_RejectsUnsafePkgName(t *testing.T) {
	t.Parallel()

	s := newStore(t)
	for _, name := range []string{"", "..", "../etc/passwd", "foo/bar", "/abs", "Foo"} {
		_, err := s.Lookup(name, "1-1")
		require.Error(t, err, name)

		err = s.Save(pkgbuild.Analysis{PkgName: name, Version: "1-1"})
		require.Error(t, err, name)
	}
}
