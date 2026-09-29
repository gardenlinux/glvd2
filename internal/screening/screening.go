// Package screening answers the coarse relevance question for a CVE:
// does it resolve to a package Garden Linux cares about?
package screening

import "github.com/gardenlinux/glvd2/internal/assessment"

// Input carries the facts screening decides on.
type Input struct {
	// Rejected is the global REJECTED signal from the CVEListV5 record.
	Rejected bool
	// CuratedMatches contains the target GL PURLs for the CVE (gl-specific inclusion).
	CuratedMatches []string
	// VendoredMatches are the parent deb-source PURLs for the CVE (vendor-mechanism).
	VendoredMatches []string
	// DebianAssigned reports that Debian assigned at least one source package to the CVE.
	DebianAssigned bool
	// DebianNotForUs is Debian's NOT-FOR-US verdict.
	DebianNotForUs bool
	// DebianAllPURLs are all Debian-assigned identity PURLs for the DST matched packages for the CVE,
	// recorded even when none of them is shipped in Garden Linux.
	DebianAllPURLs []string
	// DebianShipped is the subset of DebianAllPURLs that Garden Linux actually ships.
	DebianShipped []string
}

// Screen returns the screening verdict for the given inputs.
func Screen(in Input) assessment.ScreeningResult {
	switch {
	case in.Rejected:
		// Checked first: nothing overrides an upstream rejection.
		return decision(assessment.TriageReasonRejectedUpstream, nil)
	case len(in.CuratedMatches) > 0:
		// GL-specific inclusion override.
		return decision(assessment.TriageReasonAffectsGardenLinuxPackage, in.CuratedMatches)
	case len(in.VendoredMatches) > 0:
		// Affects a vendored component, so relevant for the actual package we build.
		return decision(assessment.TriageReasonAffectsVendoredDependency, in.VendoredMatches)
	case in.DebianAssigned:
		if len(in.DebianShipped) > 0 {
			return decision(assessment.TriageReasonAffectsDebianPackage, in.DebianShipped)
		}
		// Not shipped in GL, hence not relevant.
		return decision(assessment.TriageReasonDebianPackageNotShipped, in.DebianAllPURLs)
	case in.DebianNotForUs:
		return decision(assessment.TriageReasonDebianNotForUs, nil)
	default:
		return decision(assessment.TriageReasonAwaitingDebian, nil)
	}
}

// decision builds a ScreeningResult from a reason and its matched PURLs.
// Relevance status is derived from the reason, never set directly.
func decision(reason assessment.TriageReason, matched []string) assessment.ScreeningResult {
	return assessment.ScreeningResult{
		AutoTriage: assessment.AutoTriage{Reason: reason},
		Matched:    matched,
	}
}
