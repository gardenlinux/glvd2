package sbom_test

import (
	"context"
	"errors"
	"net/url"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/glrd"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/packages"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// source returns a ReleaseSource yielding a fixed set of releases.
func source(releases ...glrd.Release) sbom.ReleaseSource {
	return func(context.Context) ([]glrd.Release, error) {
		return releases, nil
	}
}

// failingSource returns a ReleaseSource that always fails with err.
func failingSource(err error) sbom.ReleaseSource {
	return func(context.Context) ([]glrd.Release, error) {
		return nil, err
	}
}

func release(flavors ...string) glrd.Release {
	return glrd.Release{Name: "r", Version: glrd.Version{Major: 1877, Minor: 0}, Flavors: flavors}
}

// recordingConsumer records every AddSBOM/MissingSBOMSet call and can inject errors.
type recordingConsumer struct {
	added        []*cdx.BOM
	noSBOM       []string // release names
	addErr       error
	missingError error
}

func (r *recordingConsumer) AddSBOM(bom *cdx.BOM) error {
	if r.addErr != nil {
		return r.addErr
	}
	r.added = append(r.added, bom)

	return nil
}

func (r *recordingConsumer) MissingSBOMSet(_ context.Context, rel glrd.Release) error {
	if r.missingError != nil {
		return r.missingError
	}
	r.noSBOM = append(r.noSBOM, rel.Name)

	return nil
}

// locator resolves every flavor to a per-flavor URL.
func locator() sbom.LocatorFunc {
	return func(_ glrd.Release, flavor string) (*url.URL, error) {
		return &url.URL{Scheme: "https", Host: "example", Path: "/" + flavor}, nil
	}
}

// bomNamed builds a BOM with one deb component named after the flavor path, so
// a consumer can assert which SBOM it received.
func bomNamed(path string) *cdx.BOM {
	name := "pkg" + path[1:] // "/kvm" -> "pkgkvm"
	components := []cdx.Component{{
		Type:       cdx.ComponentTypeLibrary,
		Name:       name,
		Version:    "1.0",
		PackageURL: "pkg:deb/debian/" + name + "@1.0",
	}}

	return &cdx.BOM{Components: &components}
}

func TestFeed_FeedsAddSBOMOncePerFlavorForCompleteRelease(t *testing.T) {
	t.Parallel()

	var fetched []string
	fetch := func(_ context.Context, u *url.URL) (*cdx.BOM, error) {
		fetched = append(fetched, u.Path)

		return bomNamed(u.Path), nil
	}

	col := &recordingConsumer{}
	err := sbom.Feed(t.Context(), source(release("kvm", "metal")), locator(), fetch, col)
	require.NoError(t, err)

	assert.Equal(t, []string{"/kvm", "/metal"}, fetched)
	assert.Empty(t, col.noSBOM)
	require.Len(t, col.added, 2)

	kvmPkgs, err := packages.PackageListFromSBOM(col.added[0])
	require.NoError(t, err)
	require.Len(t, kvmPkgs, 1)
	assert.Equal(t, "pkgkvm", kvmPkgs[0].Name)

	metalPkgs, err := packages.PackageListFromSBOM(col.added[1])
	require.NoError(t, err)
	require.Len(t, metalPkgs, 1)
	assert.Equal(t, "pkgmetal", metalPkgs[0].Name)
}

func TestFeed_IncompleteReleaseCallsMissingSBOMSetWithoutFetching(t *testing.T) {
	t.Parallel()

	fetchCalled := false
	locate := func(_ glrd.Release, flavor string) (*url.URL, error) {
		if flavor == "no-sbom" {
			return nil, glrd.ErrNoSBOM
		}

		return &url.URL{Scheme: "https", Host: "example", Path: "/" + flavor}, nil
	}
	fetch := func(_ context.Context, _ *url.URL) (*cdx.BOM, error) {
		fetchCalled = true

		return &cdx.BOM{}, nil
	}

	col := &recordingConsumer{}
	err := sbom.Feed(t.Context(), source(release("has-sbom", "no-sbom")), locate, fetch, col)
	require.NoError(t, err)

	// since one flavor has no SBOM; no SBOMs should be fetched
	assert.Empty(t, col.added, "no SBOM must be fed when the set is incomplete")
	assert.Equal(t, []string{"r"}, col.noSBOM)
	assert.False(t, fetchCalled, "no fetch when the set is incomplete")
}

func TestFeed_NoFlavorsCallsMissingSBOMSet(t *testing.T) {
	t.Parallel()

	fetchCalled := false
	col := &recordingConsumer{}
	err := sbom.Feed(t.Context(), source(release()), locator(),
		func(_ context.Context, _ *url.URL) (*cdx.BOM, error) {
			fetchCalled = true

			return &cdx.BOM{}, nil
		}, col)
	require.NoError(t, err)

	assert.Empty(t, col.added)
	assert.Equal(t, []string{"r"}, col.noSBOM)
	assert.False(t, fetchCalled)
}

func TestFeed_OneFetchOnly(t *testing.T) {
	t.Parallel()

	fetchCount := 0
	fetch := func(_ context.Context, u *url.URL) (*cdx.BOM, error) {
		fetchCount++

		return bomNamed(u.Path), nil
	}

	a, b := &recordingConsumer{}, &recordingConsumer{}
	err := sbom.Feed(t.Context(), source(release("kvm")), locator(), fetch, a, b)
	require.NoError(t, err)

	assert.Equal(t, 1, fetchCount, "the SBOM is fetched exactly once")
	assert.Len(t, a.added, 1)
	assert.Len(t, b.added, 1)
}

func TestFeed_AbortsOnReleaseSourceError(t *testing.T) {
	t.Parallel()

	listErr := errors.New("glrd unavailable")
	err := sbom.Feed(t.Context(), failingSource(listErr), locator(),
		func(_ context.Context, _ *url.URL) (*cdx.BOM, error) { return &cdx.BOM{}, nil }, &recordingConsumer{})
	require.ErrorIs(t, err, listErr)
}

func TestFeed_AbortsOnLocatorError(t *testing.T) {
	t.Parallel()

	locatorErr := errors.New("cannot build SBOM URL")
	err := sbom.Feed(t.Context(), source(release("kvm")),
		func(_ glrd.Release, _ string) (*url.URL, error) { return nil, locatorErr },
		func(_ context.Context, _ *url.URL) (*cdx.BOM, error) { return &cdx.BOM{}, nil }, &recordingConsumer{})
	require.ErrorIs(t, err, locatorErr)
}

func TestFeed_AbortsOnFetchError(t *testing.T) {
	t.Parallel()

	fetchErr := errors.New("network down")
	err := sbom.Feed(t.Context(), source(release("kvm")), locator(),
		func(_ context.Context, _ *url.URL) (*cdx.BOM, error) { return nil, fetchErr }, &recordingConsumer{})
	require.ErrorIs(t, err, fetchErr)
}

func TestFeed_ForwardsAddSBOMError(t *testing.T) {
	t.Parallel()

	addErr := errors.New("consumer failed")
	err := sbom.Feed(t.Context(), source(release("kvm")), locator(),
		func(_ context.Context, u *url.URL) (*cdx.BOM, error) { return bomNamed(u.Path), nil },
		&recordingConsumer{addErr: addErr})
	require.ErrorIs(t, err, addErr)
}

func TestFeed_ForwardsMissingSBOMSetError(t *testing.T) {
	t.Parallel()

	fallbackErr := errors.New("fallback failed")
	err := sbom.Feed(t.Context(), source(release()), locator(),
		func(_ context.Context, _ *url.URL) (*cdx.BOM, error) { return &cdx.BOM{}, nil },
		&recordingConsumer{missingError: fallbackErr})
	require.ErrorIs(t, err, fallbackErr)
}

// countingConsumer counts completed AddSBOM calls so the fetch stub can assert the
// previous SBOM was folded (and thus released) before the next fetch.
type countingConsumer struct {
	added int
}

func (c *countingConsumer) AddSBOM(_ *cdx.BOM) error {
	c.added++

	return nil
}

func (c *countingConsumer) MissingSBOMSet(_ context.Context, _ glrd.Release) error { return nil }

// Check that the SBOMs are handeled one by one.
func TestFeed_HoldsOneSBOMAtATime(t *testing.T) {
	t.Parallel()

	const flavorCount = 50
	flavors := make([]string, flavorCount)
	for i := range flavors {
		flavors[i] = "f" + string(rune('a'+i%26)) + string(rune('a'+i/26))
	}

	col := &countingConsumer{}
	fetches := 0
	fetch := func(_ context.Context, u *url.URL) (*cdx.BOM, error) {
		require.Equal(t, fetches, col.added,
			"the previous parsed SBOM must be folded and released before the next fetch")
		fetches++

		return bomNamed(u.Path), nil
	}

	err := sbom.Feed(t.Context(), source(release(flavors...)), locator(), fetch, col)
	require.NoError(t, err)

	assert.Equal(t, flavorCount, fetches)
	assert.Equal(t, flavorCount, col.added)
}
