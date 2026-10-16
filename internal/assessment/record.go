package assessment

import (
	"encoding/json"
	"time"
)

// Record represents our knowledge and decisions about a CVE.
type Record struct {
	ID        string                     `json:"id"                 merge:"key"`
	Upstream  UpstreamData               `json:"upstream,omitzero"  merge:"overwrite"`
	Screening ScreeningResult            `json:"screening,omitzero" merge:"overwrite"`
	Manual    ManualOverride             `json:"manual,omitzero"    merge:"preserve"`
	Meta      Metadata                   `json:"meta,omitzero"      merge:"preserve"`
	Releases  map[string]ReleaseDecision `json:"releases,omitempty" merge:"map,preserve"`
}

// CVEState is the global lifecycle state of a CVE record.
type CVEState string

const (
	CVEStatePublished CVEState = "PUBLISHED"
	CVEStateRejected  CVEState = "REJECTED"
)

// UpstreamData is ingested from CVEListV5 - purely derived from external sources.
type UpstreamData struct {
	Description string     `json:"description,omitempty"`
	CVSSv3      *CVSSScore `json:"cvss_v3,omitzero"`
	CVSSv4      *CVSSScore `json:"cvss_v4,omitzero"`
	CWEs        []string   `json:"cwes,omitempty"`
	PublishedAt time.Time  `json:"published_at,omitzero"`
	References  []string   `json:"references,omitempty"`
	State       CVEState   `json:"state,omitempty"`
}

// CVSSScore holds a CVSS score and its vector string.
type CVSSScore struct {
	Score  float64 `json:"score"`
	Vector string  `json:"vector,omitempty"`
}

// ScreeningResult is what the program computes during matching and triage.
type ScreeningResult struct {
	AutoTriage AutoTriage `json:"auto_triage,omitzero"`
	Matched    []string   `json:"matched,omitempty"`
}

// ManualOverride is human-provided data - never touched by the program.
type ManualOverride struct {
	ManualTriage ManualTriage `json:"manual_triage,omitzero"`
	Notes        string       `json:"notes,omitempty"`
}

// Metadata is set once as a side effect and preserved across runs.
type Metadata struct {
	IssueNumber int       `json:"issue_number,omitempty"`
	FirstSeenAt time.Time `json:"first_seen_at,omitzero"`
}

// TriageStatus represents the global triage decision for a CVE's relevance to Garden Linux.
type TriageStatus string

const (
	// StatusUndecided means no decision has been made yet.
	StatusUndecided TriageStatus = ""
	// StatusRelevant means the CVE affects Garden Linux and needs attention.
	StatusRelevant TriageStatus = "relevant"
	// StatusNotRelevant means the CVE does not affect Garden Linux.
	StatusNotRelevant TriageStatus = "not-relevant"
)

// TriageReason is the encoded decision the auto-triage made with the current data.
// The actual status (undecided, relevant, or not-relevant) is derived from this reason.
type TriageReason string

const (
	// TriageReasonAffectsDebianPackage means the CVE affects a Debian package. Status: relevant.
	TriageReasonAffectsDebianPackage TriageReason = "affects-debian-package"
	// TriageReasonAffectsGardenLinuxPackage means the CVE affects a Garden Linux package. Status: relevant.
	TriageReasonAffectsGardenLinuxPackage TriageReason = "affects-gardenlinux-package"
	// TriageReasonAffectsVendoredDependency means the CVE affects a non-deb component vendored
	// into a Garden Linux package. Status: relevant.
	TriageReasonAffectsVendoredDependency TriageReason = "affects-vendored-dependency"
	// TriageReasonRejectedUpstream means the CVE was rejected upstream. Status: not-relevant.
	TriageReasonRejectedUpstream TriageReason = "rejected-upstream"
	// TriageReasonDebianNotForUs means the Debian Security Tracker marks the package as not-for-us. Status:
	// not-relevant.
	TriageReasonDebianNotForUs TriageReason = "debian-not-for-us"
	// TriageReasonDebianPackageNotShipped means the Debian package is not shipped by Garden Linux. Status:
	// not-relevant.
	TriageReasonDebianPackageNotShipped TriageReason = "debian-package-not-shipped"
	// TriageReasonAwaitingDebian means the CVE is pending a Debian triage decision. Status: undecided.
	TriageReasonAwaitingDebian TriageReason = "awaiting-debian"
)

// AutoTriage is the program-owned triage result. It holds only a TriageReason; the
// TriageStatus is derived and emitted in JSON for human readability, but is never
// stored as a field - TriageReason is the single source of truth.
type AutoTriage struct {
	Reason TriageReason `json:"reason,omitempty"`
}

// diffTransparent opts AutoTriage out of opaque-leaf diffing so the diff walker
// recurses into its exported Reason field instead of comparing the marshaled JSON blob.
func (AutoTriage) diffTransparent() {}

// Status returns the derived TriageStatus for the AutoTriage's Reason.
func (a AutoTriage) Status() TriageStatus {
	switch a.Reason {
	case TriageReasonAffectsDebianPackage,
		TriageReasonAffectsGardenLinuxPackage,
		TriageReasonAffectsVendoredDependency:
		return StatusRelevant
	case TriageReasonRejectedUpstream, TriageReasonDebianNotForUs, TriageReasonDebianPackageNotShipped:
		return StatusNotRelevant
	case TriageReasonAwaitingDebian, "":
		return StatusUndecided
	}

	return StatusUndecided
}

// IsEmpty returns true if the AutoTriage has no reason set.
func (a AutoTriage) IsEmpty() bool {
	return a.Reason == ""
}

// autoTriageJSON is the enriched struct emitted by AutoTriage.MarshalJSON.
type autoTriageJSON struct {
	Status string       `json:"status,omitempty"`
	Reason TriageReason `json:"reason,omitempty"`
}

// MarshalJSON emits both reason for the decision and the derived, output-only status.
// UnmarshalJSON is not overridden so the output-only status is ignored on read.
func (a AutoTriage) MarshalJSON() ([]byte, error) {
	v := autoTriageJSON{
		Reason: a.Reason,
	}
	if s := a.Status(); s != StatusUndecided {
		v.Status = string(s)
	}
	return json.Marshal(v)
}

// ManualTriage is the human-owned triage result.
type ManualTriage struct {
	Status        TriageStatus `json:"status,omitempty"`
	Justification string       `json:"justification,omitempty"`
}

// IsEmpty returns true if the ManualTriage has no status set.
func (m ManualTriage) IsEmpty() bool {
	return m.Status == StatusUndecided
}

// ReleaseStatus is the per-release affectedness of a CVE.
type ReleaseStatus string

const (
	// ReleaseStatusUnknown means we could not determine the status.
	ReleaseStatusUnknown ReleaseStatus = "unknown"
	// ReleaseStatusAffected means this release ships a vulnerable package.
	ReleaseStatusAffected ReleaseStatus = "affected"
	// ReleaseStatusNotAffected means this release is not impacted.
	ReleaseStatusNotAffected ReleaseStatus = "not-affected"
	// ReleaseStatusFixed means this release ships the fix.
	ReleaseStatusFixed ReleaseStatus = "fixed"
)

// ReleaseStatusReason is the encoded per-package decision and the single source of truth
// from which the [ReleaseStatus] and the escalation flag are derived.
type ReleaseStatusReason string

const (
	// ReleaseReasonPackageNotShipped means the package is not shipped in the release.
	ReleaseReasonPackageNotShipped ReleaseStatusReason = "package-not-shipped"
	// ReleaseReasonDeclaredNotAffected means an authority declared the package not vulnerable.
	ReleaseReasonDeclaredNotAffected ReleaseStatusReason = "declared-not-affected"
	// ReleaseReasonVersionFixed means the shipped version is at or above the fix.
	ReleaseReasonVersionFixed ReleaseStatusReason = "version-fixed"
	// ReleaseReasonVersionVulnerable means the shipped version falls in the vulnerable range.
	ReleaseReasonVersionVulnerable ReleaseStatusReason = "version-vulnerable"
	// ReleaseReasonAffectedEscalated means the package is presumed affected with no fix to bound
	// against and needs human confirmation.
	ReleaseReasonAffectedEscalated ReleaseStatusReason = "affected-escalated"
	// ReleaseReasonUnknownEscalated means no authority could decide and a human must look.
	ReleaseReasonUnknownEscalated ReleaseStatusReason = "unknown-escalated"
)

// Status returns the derived [ReleaseStatus] for the reason.
func (r ReleaseStatusReason) Status() ReleaseStatus {
	switch r {
	case ReleaseReasonPackageNotShipped, ReleaseReasonDeclaredNotAffected:
		return ReleaseStatusNotAffected
	case ReleaseReasonVersionFixed:
		return ReleaseStatusFixed
	case ReleaseReasonVersionVulnerable, ReleaseReasonAffectedEscalated:
		return ReleaseStatusAffected
	case ReleaseReasonUnknownEscalated:
		return ReleaseStatusUnknown
	}

	return ""
}

// NeedsEscalation reports whether the reason warrants a human escalation.
func (r ReleaseStatusReason) NeedsEscalation() bool {
	return r == ReleaseReasonAffectedEscalated || r == ReleaseReasonUnknownEscalated
}

// PackageStatus is the per-package release decision for one shipped matched package.
// The package is a source package name: the map key is its source identity PURL and
// ShippedVersion is the source version compared against the vulnerable range.
type PackageStatus struct {
	Reason          ReleaseStatusReason `json:"reason,omitempty"`
	ShippedVersion  string              `json:"shipped_version,omitempty"`
	VulnerableRange string              `json:"vulnerable_range,omitempty"`
	Authority       string              `json:"authority,omitempty"`
	Provenance      string              `json:"provenance,omitempty"`
	Basis           string              `json:"basis,omitempty"`
	BasisWhy        string              `json:"basis_why,omitempty"`
	// Vendored flags that the CVE concerns a component embedded in this package, not the package itself.
	// Component and ComponentVersion name that dependency.
	Vendored         bool   `json:"vendored,omitempty"`
	Component        string `json:"component,omitempty"`
	ComponentVersion string `json:"component_version,omitempty"`
}

// Status returns the derived [ReleaseStatus] for the package's reason.
func (s PackageStatus) Status() ReleaseStatus { return s.Reason.Status() }

// MarshalJSON emits the per-package reason plus the derived, output-only status.
// UnmarshalJSON is not overridden so the output-only status is ignored on read.
func (s PackageStatus) MarshalJSON() ([]byte, error) {
	type alias PackageStatus
	return json.Marshal(struct {
		alias

		Status ReleaseStatus `json:"status,omitempty"`
	}{alias: alias(s), Status: s.Reason.Status()})
}

// PackageOverride is a human's per-package release override. The reasoning goes in the justification.
type PackageOverride struct {
	Status        ReleaseStatus `json:"status,omitempty"`
	Justification string        `json:"justification,omitempty"`
}

// IsEmpty returns true if the override has no status set.
func (o PackageOverride) IsEmpty() bool { return o.Status == "" }

// AutoReleaseStatus is the program-computed per-package breakdown for a release,
// keyed by the shipped source package's identity PURL. Only shipped packages appear.
type AutoReleaseStatus struct {
	Packages map[string]PackageStatus `json:"packages,omitempty"`
}

// ManualReleaseStatus holds human per-package overrides for a release, keyed like the auto breakdown.
type ManualReleaseStatus struct {
	Packages map[string]PackageOverride `json:"packages,omitempty"`
}

// ReleaseDecision holds the auto and manual per-package decisions for a GL release.
// The release-level composite is derived on read from the effective per-package set (manual over auto).
type ReleaseDecision struct {
	Auto   AutoReleaseStatus   `json:"auto,omitzero"   merge:"overwrite"`
	Manual ManualReleaseStatus `json:"manual,omitzero" merge:"preserve"`
}

// Rank order reasons from strongest (0) to weakest for the release roll-up.
const (
	rankVersionVulnerable = iota
	rankAffectedEscalated
	rankUnknownEscalated
	rankVersionFixed
	rankDeclaredNotAffected
)

// rankUnranked drops package-not-shipped and unset reasons as N/A.
const rankUnranked = -1

// compositeRank returns the precedence rank of a reason, or rankUnranked when it is dropped.
func compositeRank(r ReleaseStatusReason) int {
	switch r {
	case ReleaseReasonVersionVulnerable:
		return rankVersionVulnerable
	case ReleaseReasonAffectedEscalated:
		return rankAffectedEscalated
	case ReleaseReasonUnknownEscalated:
		return rankUnknownEscalated
	case ReleaseReasonVersionFixed:
		return rankVersionFixed
	case ReleaseReasonDeclaredNotAffected:
		return rankDeclaredNotAffected
	case ReleaseReasonPackageNotShipped:
		return rankUnranked
	}

	return rankUnranked
}

// effectiveReasons returns the per-package reason, manual override applied over auto.
func (d ReleaseDecision) effectiveReasons() map[string]ReleaseStatusReason {
	out := make(map[string]ReleaseStatusReason, len(d.Auto.Packages))
	for key, ps := range d.Auto.Packages {
		out[key] = ps.Reason
	}
	for key, override := range d.Manual.Packages {
		if !override.IsEmpty() {
			out[key] = reasonForOverride(override.Status)
		}
	}

	return out
}

// reasonForOverride maps a human-asserted status to a representative reason for ranking.
// A manual decision is final, so an affected override maps to non-escalating version-vulnerable.
func reasonForOverride(s ReleaseStatus) ReleaseStatusReason {
	switch s {
	case ReleaseStatusAffected:
		return ReleaseReasonVersionVulnerable
	case ReleaseStatusFixed:
		return ReleaseReasonVersionFixed
	case ReleaseStatusNotAffected:
		return ReleaseReasonDeclaredNotAffected
	case ReleaseStatusUnknown:
		return ReleaseReasonUnknownEscalated
	}

	return ReleaseReasonUnknownEscalated
}

// CompositeReason derives the release-headline reason: the highest-precedence effective reason wins,
// so one vulnerable package keeps the release affected.
// package-not-shipped packages are dropped (mapped to rankUnranked). If none remain,
// the release is package-not-shipped.
func (d ReleaseDecision) CompositeReason() ReleaseStatusReason {
	best := ReleaseStatusReason("")
	bestRank := rankUnranked
	for _, reason := range d.effectiveReasons() {
		rank := compositeRank(reason)
		if rank == rankUnranked {
			continue
		}
		if bestRank == rankUnranked || rank < bestRank {
			bestRank = rank
			best = reason
		}
	}
	if best == "" {
		return ReleaseReasonPackageNotShipped
	}

	return best
}

// CompositeStatus derives the release-headline status.
func (d ReleaseDecision) CompositeStatus() ReleaseStatus { return d.CompositeReason().Status() }

// NeedsEscalation reports whether the composite reason warrants a human escalation.
func (d ReleaseDecision) NeedsEscalation() bool { return d.CompositeReason().NeedsEscalation() }

// MarshalJSON emits the auto/manual blocks plus the derived, output-only composite.
// UnmarshalJSON is not overridden so the composite is ignored on read.
func (d ReleaseDecision) MarshalJSON() ([]byte, error) {
	type alias ReleaseDecision
	type composite struct {
		Status    ReleaseStatus       `json:"status,omitempty"`
		Reason    ReleaseStatusReason `json:"reason,omitempty"`
		Escalates bool                `json:"escalates,omitempty"`
	}
	reason := d.CompositeReason()

	return json.Marshal(struct {
		alias

		Composite composite `json:"composite"`
	}{
		alias:     alias(d),
		Composite: composite{Status: reason.Status(), Reason: reason, Escalates: reason.NeedsEscalation()},
	})
}

// GetGlobalStatus returns the effective triage status (manual overrides auto).
func (r Record) GetGlobalStatus() TriageStatus {
	if r.Manual.ManualTriage.Status != StatusUndecided {
		return r.Manual.ManualTriage.Status
	}

	return r.Screening.AutoTriage.Status()
}

// GetReleaseStatus returns the effective composite status for a release (manual over auto,
// rolled up), or [ReleaseStatusUnknown] when the release has no decision.
func (r Record) GetReleaseStatus(release string) ReleaseStatus {
	rd, ok := r.Releases[release]
	if !ok {
		return ReleaseStatusUnknown
	}

	return rd.CompositeStatus()
}
