package packages_test

import (
	"testing"

	"github.com/gardenlinux/glvd2/internal/gardenlinux/packages"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/version"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPackageUrl(t *testing.T) {
	t.Parallel()

	release := version.GardenLinuxRelease{}
	err := release.ParseFromString("1877.10")
	require.NoError(t, err)

	packageFile := packages.PackageFile{PackagePath: "main/binary-amd64/Packages"}

	url := packages.BuildPackageURL(release, packageFile)
	assert.Equal(t, "https://packages.gardenlinux.io/gardenlinux/dists/1877.10/main/binary-amd64/Packages", url, "URL should match expectations") //nolint:golines,lll // just parameters
}

func TestParseInReleaseFileEmpty(t *testing.T) {
	t.Parallel()

	_, err := packages.ParseInReleaseFile("")

	require.Error(t, err)
	assert.EqualError(t, err, "empty inrelease file")
}

func TestParseInReleaseFileBlank(t *testing.T) {
	t.Parallel()

	_, err := packages.ParseInReleaseFile("           ")

	require.Error(t, err)
	assert.EqualError(t, err, "empty inrelease file")
}

func TestArchitectures(t *testing.T) {
	t.Parallel()

	assert.Len(t, packages.ArchitectureToName, 3, "should only have all, amd and arm64")
}

func TestComponents(t *testing.T) {
	t.Parallel()

	assert.Len(t, packages.ComponentToName, 1, "should only have one component")
}

func TestParseInReleaseFile(t *testing.T) {
	t.Parallel()

	content := `
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Origin: GardenLinux
Codename: 1877.14
Description: https://github.com/gardenlinux/repo/actions/runs/23339558531
Components: main
Architectures: all amd64 arm64
Date: Fri, 20 Mar 2026 12:09:03 +0000
Valid-Until: Wed, 20 Mar 2126 12:09:03 +0000
SHA256:
 c37de74258fd64749b1f01eda963dc177d6fba8e9f80d34394a2bc9d68b7e434 1096737 main/binary-all/Packages
 56532ae360e3741c17ebb715a519034da8909d355d2ea1be0099db3009a09493 318832 main/binary-all/Packages.gz
 9bf406e897e0869649a0a87a4fccd99e64fa8ea0798b3feeb93278b3ec2b125a 2990957 main/binary-amd64/Packages
 21d56e443b7fb44a4254b69d51a95b829b81478f43aaa190f6c4fd4cb5339f49 871597 main/binary-amd64/Packages.gz
 7d74b0c33ca8664dd24b5025cb4663890758096803db1dab657ce4b663ffd289 2948940 main/binary-arm64/Packages
 846d3af4e15d50b2885364f5535e4d8809193a64baca13fb988df3b7157aff89 851502 main/binary-arm64/Packages.gz
 5a88e381ed68c98428fc7698d81c25c147ee09d568cbeccd9b17779cbde36134 3102033 main/source/Sources
 5d5534c3a7bfc418a8ed72cb58b03fc48f09591653fc86a245776c32cea43d79 778820 main/source/Sources.gz

-----BEGIN PGP SIGNATURE-----

iQIzBAEBCgAdFiEE3v04HGO2vKe8yl560pyAJHXtovsFAmm9ON8ACgkQ0pyAJHXt
ovsMPA/9HQgHi8N+BTeUACkKeMb+pqI47Twi6it+zh4PMJ7Hplpi456pPhgZNqwS
/YjfpQNXhANO37DZ6vCZe/66EyIK0Q1/Cc1Xk6+eNOMHJFHSqbbS1f707GTixC8z
A2i0n+/u2H6EvNJpuS5SWn77BcA76+bkjrcCvw1tLhUbhdEiiBsi30+SVf8oZSHb
rXpjB3ybMOGgMcFUaRGylIaCbXvSeBHDT3lweQs7zUSbv+T7PxU0YQhDz92ZQm7r
nFjCFdZ4pJLPrmhxHjSu7S39O6fH1o2YZ2kBykuH2MdSGnuadQ37OGky7WZuAkbU
c47tPuCutLE3pAD5CkJA/KOMzGDHG8pR+lYqi3dP7pVo1iGSK8JhU2k+lfd8SEg9
5YB/DGsefjESRBRhz221E6WbEyi17klaqen4kOLGOo7rcG84zmJyNFXQKkSoV6Dt
uuMSWIsz7lWSos/A8XAnM0TSlq8rTRgFDp6gKn4WP1pIyP/WuKO3IZNJo/hSnJkJ
HCMCltuHf0nZQGw49Ry8Vhesl6iWFefXPWtaB9LapdizuGIyoqwocXijYTAnSjVp
RViqfzu1SOb600c4sgA432pGVflF1L8vbtHStKGPoPgzknsngsWSJHW03wD0ObPu
vDYmziyeV/379UIrpWZIOPplKxysAM2Nz/PvmULnO5hduCz/69w=
=WWE5
-----END PGP SIGNATURE-----
	`

	expectedComponents := []packages.Component{packages.ComponentMain}
	expectedArchitectures := []packages.Architecture{
		packages.ArchitectureAll,
		packages.ArchitectureAmd64,
		packages.ArchitectureArm64,
	}
	expectedPackageLists := []packages.PackageFile{
		{
			Sha256Sum:   "56532ae360e3741c17ebb715a519034da8909d355d2ea1be0099db3009a09493",
			Size:        318832,
			PackagePath: "main/binary-all/Packages.gz",
		},
		{
			Sha256Sum:   "21d56e443b7fb44a4254b69d51a95b829b81478f43aaa190f6c4fd4cb5339f49",
			Size:        871597,
			PackagePath: "main/binary-amd64/Packages.gz",
		},
		{
			Sha256Sum:   "846d3af4e15d50b2885364f5535e4d8809193a64baca13fb988df3b7157aff89",
			Size:        851502,
			PackagePath: "main/binary-arm64/Packages.gz",
		},
	}

	inrelease, err := packages.ParseInReleaseFile(content)
	require.NoError(t, err)

	glr := version.GardenLinuxRelease{}
	err = glr.ParseFromString("1877.14")
	require.NoError(t, err)

	assert.Equal(t, glr, inrelease.Codename, "should find release 1877.14")
	assert.Len(t, inrelease.Components, len(expectedComponents), "should find only the one expected component")
	assert.Equal(t, expectedComponents, inrelease.Components, "should find component main")
	//nolint:golines // unsure what is the problem here
	assert.Len(t, inrelease.Architectures, len(expectedArchitectures), "should find only the three expected architectures")
	assert.Equal(t, expectedArchitectures, inrelease.Architectures, "should find all, amd and arm64")
	assert.Equal(t, expectedPackageLists, inrelease.PackageFiles, "should find all compressed package lists")
}

func TestParsePackageList(t *testing.T) {
	t.Parallel()

	// Note: has extra line at the end
	//nolint:nolintlint,lll // text passage is just long
	content := `Package: node-escodegen
Version: 2.1.0+dfsg+~0.0.8-1
Architecture: all
Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Installed-Size: 141
Depends: node-esprima, node-estraverse, node-esutils, node-optionator, node-source-map, nodejs:any
Provides: node-types-escodegen (= 0.0.8)
Filename: pool/a9dab2997239c24c3841a81b2122216667631c4a9c86dff6317c4dce8ecd894d/node-escodegen_2.1.0+dfsg+~0.0.8-1_all.deb
Size: 22952
MD5sum: 9581840bd695a46e56d1a0d7b7cddb89
SHA1: 87621100efad3c0355d449c5b38d6d25fd6129b3
SHA256: a9dab2997239c24c3841a81b2122216667631c4a9c86dff6317c4dce8ecd894d
Section: javascript
Priority: optional
Homepage: https://github.com/estools/escodegen
Description: ECMAScript code generator
 This is an ECMAScript (also popularly known as JavaScript) code generator
 from Mozilla's Parser API AST.
 .
 Node.js is an event-based server-side JavaScript engine.

Package: node-eslint-scope
Version: 7.1.1+~3.7.4-1
Architecture: all
Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Installed-Size: 299
Depends: nodejs, node-esrecurse, node-estraverse
Provides: node-types-eslint-scope (= 3.7.4~7.1.1+~3.7.4-1)
Filename: pool/50d619d48663ce3badfce5a4bb2af3ff0d3c16cf1785130a94d22a8c13a2b180/node-eslint-scope_7.1.1+~3.7.4-1_all.deb
Size: 35596
MD5sum: 61ed81479c89b71defac775da577fe4c
SHA1: 86cd221d823d91dc21f374037649e76335707822
SHA256: 50d619d48663ce3badfce5a4bb2af3ff0d3c16cf1785130a94d22a8c13a2b180
Section: javascript
Priority: optional
Homepage: https://github.com/eslint/eslint-scope
Description: ECMAScript scope analyzer for ESLint
 ESLint Scope is the ECMAScript (a.k.a. JavaScrip) scope analyzer
 used in ESLint.
 .
 It is a fork of escope.

Package: node-eslint-utils
Version: 3.0.0-3
Architecture: all
Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Installed-Size: 81
Depends: node-eslint-visitor-keys
Filename: pool/5313c25e6c0c0a6476cf716788294918e0cb0c5fc16594ee4aa0712cb682ffc8/node-eslint-utils_3.0.0-3_all.deb
Size: 15452
MD5sum: f40d08e48219e8b1a120b3ea6ff08f52
SHA1: a34d3cece81537e48b6decf8738e614b5038267a
SHA256: 5313c25e6c0c0a6476cf716788294918e0cb0c5fc16594ee4aa0712cb682ffc8
Section: javascript
Priority: optional
Multi-Arch: foreign
Homepage: https://github.com/mysticatea/eslint-utils
Description: utilities for ESLint plugins
 eslint-utils provides utility functions and classes
 for making ESLint custom rules.
 .
 ESLint is a tool for identifying and reporting on patterns
 found in ECMAScript/JavaScript code.
 .
 Node.js is an event-based server-side JavaScript engine.


`

	pkgs, err := packages.ParsePackageList(content)

	assert.Len(t, pkgs, 3)
	assert.NoError(t, err, "should not have errors")
}
