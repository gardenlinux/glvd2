package types

import (
	"testing"

	"github.com/gardenlinux/glvd2/internal/gardenlinux/glrd"

	"github.com/stretchr/testify/assert"
)

func TestParseFromString(t *testing.T) {
	obj := GardenLinuxRelease{}
	err := obj.ParseFromString("1.2.3")

	assert.NotNil(t, err)
	assert.Equal(t, "Prior semver version expects only two version parts.", err.Error())
}

func TestParseFromStringBeforeSemver(t *testing.T) {
	obj := GardenLinuxRelease{}
	err := obj.ParseFromString("1.2")

	assert.Nil(t, err)
	assert.Equal(t, GardenLinuxRelease{Name: "1.2", Major: 1, Minor: 2, Patch: 0, SemVer: false}, obj, "should be equal")
}

func TestParseFromStringSemver(t *testing.T) {
	obj := GardenLinuxRelease{}
	err := obj.ParseFromString("2017.0.0")

	assert.Nil(t, err)
	assert.Equal(t, GardenLinuxRelease{Name: "2017.0.0", Major: 2017, Minor: 0, Patch: 0, SemVer: true}, obj, "should be equal")
}

func TestParseFromStringSemverMismatchAfter(t *testing.T) {
	obj := GardenLinuxRelease{}
	err := obj.ParseFromString("2017.0")

	assert.NotNil(t, err)
	assert.Equal(t, "Semver version schema expects three version parts.", err.Error())
}

func TestParseFromStringSemverMismatchBefore(t *testing.T) {
	obj := GardenLinuxRelease{}
	err := obj.ParseFromString("2016.0.0")

	assert.NotNil(t, err)
	assert.Equal(t, "Prior semver version expects only two version parts.", err.Error())
}

func TestParseFromStringOutOfUpperBounds(t *testing.T) {
	obj := GardenLinuxRelease{}
	err := obj.ParseFromString("1.2.3.4.5.6")

	assert.NotNil(t, err)
	assert.Equal(t, "invalid version schema", err.Error())
}

func TestParseFromStringOutOfLowerBounds(t *testing.T) {
	obj := GardenLinuxRelease{}
	err := obj.ParseFromString("1")

	assert.NotNil(t, err)
}

func TestParseFromStringPartial(t *testing.T) {
	obj := GardenLinuxRelease{}
	err := obj.ParseFromString("1.")

	assert.NotNil(t, err)
}

func TestParseFromGlrdVersion(t *testing.T) {
	glrdVersion := glrd.Version{Major: 1, Minor: 2, Patch: 3}
	obj := GardenLinuxRelease{}
	err := obj.ParseFromGlrdVersion(glrdVersion)

	assert.Nil(t, err)
	assert.Equal(t, GardenLinuxRelease{Name: "1.2.3", Major: 1, Minor: 2, Patch: 3, SemVer: true}, obj, "should be equal")
}

func TestFormat(t *testing.T) {
	glrdVersion := GardenLinuxRelease{Major: 1, Minor: 2, Patch: 3, SemVer: true}
	assert.Equal(t, "1.2.3", glrdVersion.Format(), "should be correctly formatted")
}

func TestBeforeSemver(t *testing.T) {
	glrdVersion := GardenLinuxRelease{Major: 1877, Minor: 14, Patch: 0, SemVer: false}
	assert.Equal(t, "1877.14", glrdVersion.Format(), "should be correctly formatted")
}

func TestBeforeSemverFromVersion(t *testing.T) {
	glr := GardenLinuxRelease{}
	err := glr.ParseFromString("1877.14")

	assert.Nil(t, err)
	assert.Equal(t, "1877.14", glr.Format(), "should be correctly formatted")
}

func TestAfterSemverFromVersion(t *testing.T) {
	glr := GardenLinuxRelease{}
	err := glr.ParseFromString("2150.1.2")

	assert.Nil(t, err)
	assert.Equal(t, "2150.1.2", glr.Format(), "should be correctly formatted")
}
