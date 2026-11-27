package presentation

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// releaseVersionRegex matches a major.minor or major.minor.patch release version string.
var releaseVersionRegex = regexp.MustCompile(`^(?P<major>\d+)\.(?P<minor>\d+)(?:\.(?P<patch>\d+))?$`)

// compareReleaseVersions orders release version strings numerically. Strings that are neither
// major.minor nor major.minor.patch sort after parseable ones, lexically among themselves, so the
// ordering is total and deterministic.
func compareReleaseVersions(a, b string) int {
	fa, okA := releaseVersionFields(a)
	fb, okB := releaseVersionFields(b)
	switch {
	case !okA && !okB:
		return strings.Compare(a, b)
	case !okA:
		return 1
	case !okB:
		return -1
	default:
		return slices.Compare(fa, fb)
	}
}

// compareReleaseVersionsDesc orders release version strings by descending version number, so the
// newest release sorts first. Strings that are neither major.minor nor major.minor.patch still sort
// after parseable ones, lexically among themselves, keeping the ordering total and deterministic.
func compareReleaseVersionsDesc(a, b string) int {
	fa, okA := releaseVersionFields(a)
	fb, okB := releaseVersionFields(b)
	switch {
	case !okA && !okB:
		return strings.Compare(a, b)
	case !okA:
		return 1
	case !okB:
		return -1
	default:
		return slices.Compare(fb, fa)
	}
}

// releaseVersionFields parses a release version string into its numeric components.
// It returns false when s matches neither major.minor nor major.minor.patch.
func releaseVersionFields(s string) ([]int, bool) {
	m := releaseVersionRegex.FindStringSubmatch(s)
	if m == nil {
		return nil, false
	}

	fields := make([]int, 0, len(m)-1)
	for _, g := range m[1:] {
		if g == "" {
			break
		}

		n, err := strconv.Atoi(g) // group contains only digits
		if err != nil {
			return nil, false
		}
		fields = append(fields, n)
	}

	return fields, true
}

// cveIDRegex matches a CVE ID and captures its year and sequence number.
var cveIDRegex = regexp.MustCompile(`^CVE-(\d{4})-(\d+)$`)

// compareCVEIDs orders CVE IDs by year then numeric sequence.
// IDs that do not parse sort after parseable ones, lexically among themselves.
// The return value is any negative/zero/positive integer, as required by slices.SortFunc.
func compareCVEIDs(a, b string) int {
	ya, sa, okA := cveIDFields(a)
	yb, sb, okB := cveIDFields(b)
	switch {
	case !okA && !okB:
		return strings.Compare(a, b)
	case !okA:
		return 1
	case !okB:
		return -1
	}

	if ya != yb {
		return ya - yb
	}

	return sa - sb
}

// cveIDFields parses a CVE ID into its year and sequence. The final bool is false when s is not a CVE ID.
func cveIDFields(s string) (int, int, bool) {
	m := cveIDRegex.FindStringSubmatch(s)
	if m == nil {
		return 0, 0, false
	}

	year, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, 0, false
	}

	seq, err := strconv.Atoi(m[2])
	if err != nil {
		return 0, 0, false
	}

	return year, seq, true
}
