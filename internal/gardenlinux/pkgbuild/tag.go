package pkgbuild

import (
	"regexp"
	"strings"
)

// binNMUSuffix matches a Debian binNMU rebuild suffix (+bN) at the end of a version.
// A binNMU is a pure rebuild on the same source, so it shares the base version's tag,
// provenance and patches.
var binNMUSuffix = regexp.MustCompile(`\+b\d+$`)

// stripBinNMU removes a trailing binNMU suffix, yielding the base source version.
func stripBinNMU(version string) string {
	return binNMUSuffix.ReplaceAllString(version, "")
}

// storeVersion normalizes a shipped version to its store key.
// binNMUs collapse to their base version (same build), while the ~bp backport form is kept.
func storeVersion(version string) string {
	return stripBinNMU(version)
}

// stripEpoch drops a Debian version epoch (everything up to and including the first ':'),
// which the GL build system removes when cutting the tag.
func stripEpoch(version string) string {
	if _, after, found := strings.Cut(version, ":"); found {
		return after
	}

	return version
}

// versionToTag maps a shipped package version to its GL git tag.
// The build system cuts the tag from the source .dsc version by stripping the epoch
// and translating every '~' to '+' (e.g. the backport suffix ~bp -> +bp).
func versionToTag(version string) string {
	// A binNMU carries no own tag (it resolves to the base source version's tag).
	tag := stripBinNMU(version)

	tag = stripEpoch(tag)

	return strings.ReplaceAll(tag, "~", "+")
}

// backportSuffix matches the GL backport marker gl<N>~bp<major> of a package version.
var backportSuffix = regexp.MustCompile(`gl\d+~bp\d+`)

// repoCandidates returns the GL package repo names that may host a source package.
// A ~bp tag lives in the package's normal repo when it has one; otherwise in a dedicated
// bp-package-<name> repo, which exists only when there is no normal repo.
func repoCandidates(pkgName, version string) []string {
	if backportSuffix.MatchString(version) {
		return []string{"package-" + pkgName, "bp-package-" + pkgName}
	}

	return []string{"package-" + pkgName}
}
