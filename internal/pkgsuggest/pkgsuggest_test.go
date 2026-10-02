package pkgsuggest_test

import (
	"testing"

	"github.com/gardenlinux/glvd2/internal/cpe"
	"github.com/gardenlinux/glvd2/internal/debmap"
	"github.com/gardenlinux/glvd2/internal/identifier"
	"github.com/gardenlinux/glvd2/internal/ingestion/cvelistv5"
	"github.com/gardenlinux/glvd2/internal/pkgsuggest"
	"github.com/stretchr/testify/assert"
)

func TestSuggest_GroupsByPackageAndRanksByTotalCount(t *testing.T) {
	t.Parallel()

	index := debmap.MatchingDebianPackages{
		VendorProductPairs: debmap.PackageCountsByID{
			`"curl":"curl"`:       {"pkg:deb/debian/curl": 5, "pkg:deb/debian/libcurl": 2},
			`"openssl":"openssl"`: {"pkg:deb/debian/openssl": 3},
		},
		CPEs: debmap.PackageCountsByID{
			"cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*": {"pkg:deb/debian/openssl": 9},
		},
		PackageIDs:  debmap.PackageCountsByID{},
		PackageURLs: debmap.PackageCountsByID{},
	}

	ids := cvelistv5.IDsForCVEs{
		"CVE-2026-0001": &cvelistv5.Identifiers{
			VendorProductPairs: []identifier.VendorProduct{
				{Vendor: "curl", Product: "curl"},
				{Vendor: "openssl", Product: "openssl"},
			},
			WFNs: cpe.NewUniqueWFNMapFrom([]cpe.WFN{
				{Part: cpe.StringAV("a"), Vendor: cpe.StringAV("openssl"), Product: cpe.StringAV("openssl")},
			}),
		},
	}

	s := pkgsuggest.New(index, ids)
	got := s.Suggest("CVE-2026-0001")

	want := []pkgsuggest.Candidate{
		{
			// openssl suggested by two identifiers (9 + 3 = 12), sorted count desc.
			PackageName: "pkg:deb/debian/openssl",
			Matches: []pkgsuggest.Match{
				{Identifier: "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*", Count: 9},
				{Identifier: `"openssl":"openssl"`, Count: 3},
			},
		},
		{
			PackageName: "pkg:deb/debian/curl",
			Matches:     []pkgsuggest.Match{{Identifier: `"curl":"curl"`, Count: 5}},
		},
		{
			PackageName: "pkg:deb/debian/libcurl",
			Matches:     []pkgsuggest.Match{{Identifier: `"curl":"curl"`, Count: 2}},
		},
	}
	assert.Equal(t, want, got)
}

func TestSuggest_UnknownCVE(t *testing.T) {
	t.Parallel()

	s := pkgsuggest.New(
		debmap.MatchingDebianPackages{VendorProductPairs: debmap.PackageCountsByID{}},
		cvelistv5.IDsForCVEs{},
	)
	assert.Nil(t, s.Suggest("CVE-2026-9999"))
}

// TestSuggest_TieBreaksAreDeterministic ensures the suggestion order stays the same between runs
// to avoid unnecessary changes to the assessment record.
func TestSuggest_TieBreaksAreDeterministic(t *testing.T) {
	t.Parallel()

	// alpha and beta both total 4 -> candidate tie-break by package name.
	// alpha is hit by two VP pairs of equal count (2) -> match tie-break by identifier.
	index := debmap.MatchingDebianPackages{
		VendorProductPairs: debmap.PackageCountsByID{
			`"a":"a"`: {"pkg:deb/debian/alpha": 2},
			`"b":"b"`: {"pkg:deb/debian/alpha": 2},
			`"c":"c"`: {"pkg:deb/debian/beta": 4},
		},
		CPEs:        debmap.PackageCountsByID{},
		PackageIDs:  debmap.PackageCountsByID{},
		PackageURLs: debmap.PackageCountsByID{},
	}

	ids := cvelistv5.IDsForCVEs{
		"CVE-2026-0003": &cvelistv5.Identifiers{
			// Declared out of alphabetical order so the sorted output cannot
			// coincide with collection order: this makes both tie-breaks load-bearing.
			VendorProductPairs: []identifier.VendorProduct{
				{Vendor: "b", Product: "b"},
				{Vendor: "a", Product: "a"},
				{Vendor: "c", Product: "c"},
			},
		},
	}

	s := pkgsuggest.New(index, ids)
	got := s.Suggest("CVE-2026-0003")

	want := []pkgsuggest.Candidate{
		{
			// Equal total with beta -> alpha wins on package name (alphabetical).
			// Equal match counts -> identifiers in alphabetical order.
			PackageName: "pkg:deb/debian/alpha",
			Matches: []pkgsuggest.Match{
				{Identifier: `"a":"a"`, Count: 2},
				{Identifier: `"b":"b"`, Count: 2},
			},
		},
		{
			PackageName: "pkg:deb/debian/beta",
			Matches:     []pkgsuggest.Match{{Identifier: `"c":"c"`, Count: 4}},
		},
	}
	assert.Equal(t, want, got)
}

func TestSuggest_NoMatches(t *testing.T) {
	t.Parallel()

	index := debmap.MatchingDebianPackages{
		VendorProductPairs: debmap.PackageCountsByID{`"x":"y"`: {"pkg:deb/debian/x": 1}},
	}
	ids := cvelistv5.IDsForCVEs{
		"CVE-2026-0002": &cvelistv5.Identifiers{
			VendorProductPairs: []identifier.VendorProduct{{Vendor: "unknown", Product: "thing"}},
		},
	}
	s := pkgsuggest.New(index, ids)
	assert.Empty(t, s.Suggest("CVE-2026-0002"))
}
