package presentation

import "github.com/gardenlinux/glvd2/internal/assessment"

// ScopeStatus is the coverage of an effectively relevant CVE within a release or flavor scope.
// It is distinct from affectedness: a CVE can be Assessed yet not-affected. Whether a release has
// flavor analysis at all is carried at release level by [Release.Flavors].
type ScopeStatus string

const (
	// ScopeStatusAssessed means the scope has a release decision contributing in-scope sources.
	// For a release that is any recorded decision. For a flavor it additionally requires at least
	// one contributing source package present in the flavor's membership.
	ScopeStatusAssessed ScopeStatus = "assessed"
	// ScopeStatusNotAssessed means the release has no recorded decision for the CVE.
	ScopeStatusNotAssessed ScopeStatus = "not-assessed"
	// ScopeStatusOutsideScope means a covered flavor has a release decision but none of the CVE's
	// contributing source packages are included in the flavor.
	ScopeStatusOutsideScope ScopeStatus = "outside-scope"
)

// ScopedCVE is one effectively relevant CVE projected into a release or flavor scope.
type ScopedCVE struct {
	// ID is the CVE identifier.
	ID string
	// SourcePackages are the sorted contributing source-package identity PURLs for the scope.
	// It is empty for a recorded-but-empty release decision and for scopes without contributing source packages.
	SourcePackages []string
	// Status is the coverage of the CVE within the scope.
	Status ScopeStatus
	// Affectedness is the composite release status when Status is Assessed. Zero otherwise.
	Affectedness assessment.ReleaseStatus
	// NeedsReview reports whether any in-scope effective package is in human escalation.
	NeedsReview bool
}

// Flavor is the projection of one flavor within a release.
type Flavor struct {
	// Name is the flavor name.
	Name string
	// CVEs are the effectively relevant CVEs with in-scope findings in this flavor, ordered by CVE year and sequence.
	CVEs []ScopedCVE
}

// PackageCVE is one recorded release decision for a relevant CVE that touches a package.
type PackageCVE struct {
	// ID is the CVE identifier.
	ID string
	// SourcePackagePURL is the original source PURL for this evidence row.
	SourcePackagePURL string
	// Release is the GL release version the decision belongs to.
	Release string
	// IsManual reports whether this row is a human override rather than an automated finding.
	IsManual bool
	// Justification carries the manual rationale, if it is a manual decision.
	Justification string
	// Status is the per-package release status for this decision.
	Status assessment.ReleaseStatus
	// Reason is the automated per-package reason. It is empty for manual rows.
	Reason assessment.ReleaseStatusReason
	// NeedsReview reports whether this row's reason warrants escalation. Manual rows never do.
	NeedsReview bool
	// The remaining fields carry the automated evidence and are empty for manual rows.
	ShippedVersion  string
	VulnerableRange string
	Authority       string
	Provenance      string
	Basis           string
	BasisWhy        string
	Vendored        bool
	Component       string
}

// Package is the aggregate projection of one Garden Linux source package across maintained
// releases, grouping the relevant CVEs that touch it with the decisions recorded for them.
type Package struct {
	// Name is the Debian source package name and the package page's URL segment.
	Name string
	// SourcePackagePURLs are the original source PURLs grouped under this name, sorted lexically.
	SourcePackagePURLs []string
	// Namespaces are the distinct namespaces of those identities, sorted lexically.
	Namespaces []string
	// CVEs are the recorded decisions touching this package, ordered newest CVE first, then by
	// release, with automated rows before manual rows.
	CVEs []PackageCVE
}

// Release is the aggregate projection of one maintained release.
type Release struct {
	// Version is the GL release version string like "1877.26".
	Version string
	// CVEs are the release's effectively relevant CVEs with a recorded decision for the release,
	// ordered by CVE year and sequence.
	CVEs []ScopedCVE
	// Flavors are the per-flavor projections, ordered by flavor name. It is empty when the
	// release has no usable flavor membership, in which case the release is presented at release
	// level only.
	Flavors []Flavor
}
