package version_test

import (
	"testing"

	"github.com/gardenlinux/glvd2/internal/gardenlinux/glrd"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/version"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseFromString(t *testing.T) {
	t.Parallel()

	obj := version.GardenLinuxRelease{}
	err := obj.ParseFromString("1.2.3")

	require.Error(t, err)
	assert.Equal(t, "prior semver version expects only two version parts", err.Error())
}

func TestParseFromStringBeforeSemver(t *testing.T) {
	t.Parallel()

	obj := version.GardenLinuxRelease{}
	err := obj.ParseFromString("1.2")

	require.NoError(t, err)
	assert.Equal(t, version.GardenLinuxRelease{
		Name:   "1.2",
		Major:  1,
		Minor:  2,
		Patch:  0,
		SemVer: false,
	}, obj, "should be equal")
}

func TestParseFromStringSemver(t *testing.T) {
	t.Parallel()

	obj := version.GardenLinuxRelease{}
	err := obj.ParseFromString("2017.0.0")
	require.NoError(t, err)
	assert.Equal(t, version.GardenLinuxRelease{
		Name:   "2017.0.0",
		Major:  2017,
		Minor:  0,
		Patch:  0,
		SemVer: true,
	}, obj, "should be equal")
}

func TestParseFromStringSemverMismatchAfter(t *testing.T) {
	t.Parallel()

	obj := version.GardenLinuxRelease{}
	err := obj.ParseFromString("2017.0")

	require.Error(t, err)
	assert.Equal(t, "semver version schema expects three version parts", err.Error())
}

func TestParseFromStringSemverMismatchBefore(t *testing.T) {
	t.Parallel()

	obj := version.GardenLinuxRelease{}
	err := obj.ParseFromString("2016.0.0")

	require.Error(t, err)
	assert.Equal(t, "prior semver version expects only two version parts", err.Error())
}

func TestParseFromStringOutOfUpperBounds(t *testing.T) {
	t.Parallel()

	obj := version.GardenLinuxRelease{}
	err := obj.ParseFromString("1.2.3.4.5.6")

	require.Error(t, err)
	assert.Equal(t, "invalid version schema", err.Error())
}

func TestParseFromStringOutOfLowerBounds(t *testing.T) {
	t.Parallel()

	obj := version.GardenLinuxRelease{}
	err := obj.ParseFromString("1")

	assert.Error(t, err)
}

func TestParseFromStringPartial(t *testing.T) {
	t.Parallel()

	obj := version.GardenLinuxRelease{}
	err := obj.ParseFromString("1.")

	assert.Error(t, err)
}

func TestParseFromGlrdVersion(t *testing.T) {
	t.Parallel()

	glrdVersion := glrd.Version{Major: 1, Minor: 2, Patch: 3}
	obj := version.GardenLinuxRelease{}
	err := obj.ParseFromGlrdVersion(glrdVersion)

	require.NoError(t, err)
	assert.Equal(t, version.GardenLinuxRelease{
		Name:   "1.2.3",
		Major:  1,
		Minor:  2,
		Patch:  3,
		SemVer: true,
	}, obj, "should be equal")
}

func TestFormat(t *testing.T) {
	t.Parallel()

	glrdVersion := version.GardenLinuxRelease{Major: 1, Minor: 2, Patch: 3, SemVer: true}
	assert.Equal(t, "1.2.3", glrdVersion.Format(), "should be correctly formatted")
}

func TestBeforeSemver(t *testing.T) {
	t.Parallel()

	glrdVersion := version.GardenLinuxRelease{Major: 1877, Minor: 14, Patch: 0, SemVer: false}
	assert.Equal(t, "1877.14", glrdVersion.Format(), "should be correctly formatted")
}

func TestBeforeSemverFromVersion(t *testing.T) {
	t.Parallel()

	glr := version.GardenLinuxRelease{}
	err := glr.ParseFromString("1877.14")

	require.NoError(t, err)
	assert.Equal(t, "1877.14", glr.Format(), "should be correctly formatted")
}

func TestAfterSemverFromVersion(t *testing.T) {
	t.Parallel()

	glr := version.GardenLinuxRelease{}
	err := glr.ParseFromString("2150.1.2")

	require.NoError(t, err)
	assert.Equal(t, "2150.1.2", glr.Format(), "should be correctly formatted")
}
