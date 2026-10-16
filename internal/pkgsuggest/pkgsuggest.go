// Package pkgsuggest suggests candidate Debian packages for a CVE by looking the CVE's own
// identifiers up against the identifier index built by the historic Debian triage.
package pkgsuggest

import (
	"cmp"
	"slices"

	"github.com/gardenlinux/glvd2/internal/cvelistv5"
	"github.com/gardenlinux/glvd2/internal/debmap"
)

// Match is one identifier's evidence for a Candidate.
type Match struct {
	// Identifier is the CVE identifier (VP pair, CPE, package ID, or PURL) that matched the package.
	Identifier string `json:"identifier"`
	// Count is how often Identifier historically mapped to the package.
	Count int `json:"count"`
}

// Candidate is a heuristic suggestion of a Debian package for a CVE, grouped per package.
type Candidate struct {
	// PackageName is the candidate Debian package as an identity PURL e.g. pkg:deb/debian/openssl.
	PackageName string `json:"package_name"`
	// Matches is the per-identifier evidence that pointed to PackageName.
	Matches []Match `json:"matches"`
}

// Suggester ranks candidate packages for a CVE.
type Suggester struct {
	index debmap.MatchingDebianPackages
	ids   cvelistv5.IDsForCVEs
}

// New constructs a package candidate Suggester.
func New(index debmap.MatchingDebianPackages, ids cvelistv5.IDsForCVEs) *Suggester {
	return &Suggester{index: index, ids: ids}
}

// Suggest ranks candidate Debian packages for the CVE's own identifiers, grouped per package.
func (s *Suggester) Suggest(cveID string) []Candidate {
	ids := s.ids[cveID]
	if ids == nil {
		return nil
	}

	byPackage := make(map[string][]Match)
	collect := func(counts debmap.PackageCountsByID, id string) {
		for pkg, count := range counts[id] {
			byPackage[pkg] = append(byPackage[pkg], Match{Identifier: id, Count: count})
		}
	}

	for _, vp := range ids.VendorProductPairs {
		collect(s.index.VendorProductPairs, vp.String())
	}
	for _, wfn := range ids.WFNs {
		collect(s.index.CPEs, wfn.FormatAsCPE23String())
	}
	for _, pID := range ids.PackageIDs {
		collect(s.index.PackageIDs, pID.String())
	}
	for _, p := range ids.PackageURLs {
		collect(s.index.PackageURLs, p)
	}

	if len(byPackage) == 0 {
		return nil
	}

	out := make([]Candidate, 0, len(byPackage))
	totals := make(map[string]int, len(byPackage))
	for pkg, matches := range byPackage {
		slices.SortFunc(matches, func(a, b Match) int {
			return cmp.Or(
				cmp.Compare(b.Count, a.Count),
				cmp.Compare(a.Identifier, b.Identifier),
			)
		})

		total := 0
		for _, m := range matches {
			total += m.Count
		}
		totals[pkg] = total

		out = append(out, Candidate{PackageName: pkg, Matches: matches})
	}

	slices.SortFunc(out, func(a, b Candidate) int {
		return cmp.Or(
			cmp.Compare(totals[b.PackageName], totals[a.PackageName]),
			cmp.Compare(a.PackageName, b.PackageName),
		)
	})

	return out
}
