// Package releasestatus assesses, per maintained release, the affectedness of a relevant CVE
// on each shipped matched package. For each package it derives an [assessment.ReleaseStatusReason]
// from the shipped version and the vulnerable-range resolver result.
package releasestatus

import (
	"github.com/gardenlinux/glvd2/internal/affectedness"
	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/gardenlinux/glvd2/internal/vers"
)

const (
	// BasisEvalUndecidable marks a package whose shipped version could not be ordered against
	// the range. It escalates as unknown, but with distinct context from a no-authority undecided.
	BasisEvalUndecidable = "eval-undecidable"
	// BasisVendoredDeferred marks a vendored match escalated because the vendored checking step
	// is deferred for this iteration.
	BasisVendoredDeferred = "vendored-deferred"
)

// vendoredWhy is the escalation note for a vendored match while this step is deferred.
const vendoredWhy = "matched via a vendored dependency; component-version analysis " +
	"is deferred, so this escalates for human review"

// Input is the pure assessor input for one relevant CVE.
type Input struct {
	// Vendored reports the CVE matched via the vendored path. While vendored analysis
	// is deferred, such matches escalate rather than compare a component version.
	Vendored bool
	// Releases holds, per maintained release, the shipped matched packages and their results.
	Releases []ReleaseInput
}

// ReleaseInput is the shipped matched packages for one release.
// Not-shipped packages are omitted; an empty set rolls up to package-not-shipped.
type ReleaseInput struct {
	Release  string
	Packages []PackageInput
}

// PackageInput is one shipped matched source package with its resolver result.
type PackageInput struct {
	// SourcePURL is the version-free source package identity PURL.
	SourcePURL string
	// ShippedVersion is the version shipped in this release.
	ShippedVersion string
	// Affectedness is the facts-only resolver output for (package, shipped version).
	Affectedness affectedness.Result
}

// Assess computes the per-release decisions for a relevant CVE, keyed by GL release string.
func Assess(in Input) map[string]assessment.ReleaseDecision {
	out := make(map[string]assessment.ReleaseDecision, len(in.Releases))
	for _, rel := range in.Releases {
		pkgs := make(map[string]assessment.PackageStatus, len(rel.Packages))
		for _, pkg := range rel.Packages {
			if in.Vendored {
				pkgs[pkg.SourcePURL] = vendoredStatus(pkg)
			} else {
				pkgs[pkg.SourcePURL] = packageStatus(pkg)
			}
		}

		var decision assessment.ReleaseDecision
		if len(pkgs) > 0 {
			decision.Auto.Packages = pkgs
		}
		out[rel.Release] = decision
	}

	return out
}

// packageStatus maps the resolver result for a shipped deb-path package to its decision.
func packageStatus(pkg PackageInput) assessment.PackageStatus {
	a := pkg.Affectedness
	ps := assessment.PackageStatus{
		ShippedVersion: pkg.ShippedVersion,
		Authority:      string(a.Authority),
		Provenance:     string(a.Provenance),
		Basis:          string(a.Basis),
		BasisWhy:       a.Why,
	}

	switch a.Outcome { //nolint:exhaustive // OutcomeUndecided is handled by the default case
	case affectedness.OutcomeFixed:
		ps.Reason = assessment.ReleaseReasonVersionFixed
	case affectedness.OutcomeNotAffected:
		ps.Reason = assessment.ReleaseReasonDeclaredNotAffected
	case affectedness.OutcomeAffectedNoRange:
		ps.Reason = assessment.ReleaseReasonAffectedEscalated
	case affectedness.OutcomeVersionRange:
		return evaluateRange(ps, a)
	default:
		// OutcomeUndecided and any unexpected outcome escalate for human review.
		ps.Reason = assessment.ReleaseReasonUnknownEscalated
	}

	return ps
}

// evaluateRange compares the pre-adapted version against the range. vers.Evaluate is
// garbage-safe: it validity-checks the operand first, so an un-orderable version becomes
// Undecidable rather than a confident wrong verdict.
func evaluateRange(ps assessment.PackageStatus, a affectedness.Result) assessment.PackageStatus {
	if a.Range == nil {
		ps.Reason = assessment.ReleaseReasonUnknownEscalated
		ps.Basis = BasisEvalUndecidable

		return ps
	}

	ps.VulnerableRange = a.Range.String()

	switch vers.Evaluate(a.Range, a.CompareVersion) {
	case vers.Within:
		ps.Reason = assessment.ReleaseReasonVersionVulnerable
	case vers.Outside:
		ps.Reason = assessment.ReleaseReasonVersionFixed
	case vers.Undecidable:
		ps.Reason = assessment.ReleaseReasonUnknownEscalated
		ps.Basis = BasisEvalUndecidable
	}

	return ps
}

// vendoredStatus escalates a vendored match. The component identity and version are not yet
// retained through the vendored path, so the comparison is deferred; the vendored origin is
// flagged so the audit and escalation make the dependency relationship explicit.
func vendoredStatus(pkg PackageInput) assessment.PackageStatus {
	return assessment.PackageStatus{
		Reason:         assessment.ReleaseReasonUnknownEscalated,
		ShippedVersion: pkg.ShippedVersion,
		Basis:          BasisVendoredDeferred,
		Vendored:       true,
		BasisWhy:       vendoredWhy,
	}
}
