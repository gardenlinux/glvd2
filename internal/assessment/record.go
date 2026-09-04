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

// UpstreamData is ingested from CVEListV5 - purely derived from external sources.
type UpstreamData struct {
	Description string     `json:"description,omitempty"`
	CVSSv3      *CVSSScore `json:"cvss_v3,omitzero"`
	CVSSv4      *CVSSScore `json:"cvss_v4,omitzero"`
	CWEs        []string   `json:"cwes,omitempty"`
	PublishedAt time.Time  `json:"published_at,omitzero"`
	References  []string   `json:"references,omitempty"`
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
	case TriageReasonAffectsDebianPackage, TriageReasonAffectsGardenLinuxPackage:
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

// ImpactStatus represents the per-release impact of a CVE.
type ImpactStatus string

const (
	// ImpactUnknown means the impact has not yet been determined.
	ImpactUnknown ImpactStatus = ""
	// ImpactAffected means this release ships the vulnerable version.
	ImpactAffected ImpactStatus = "affected"
	// ImpactNotAffected means this release is not impacted.
	ImpactNotAffected ImpactStatus = "not-affected"
	// ImpactFixed means this release contains the fix.
	ImpactFixed ImpactStatus = "fixed"
)

// ReleaseTriage holds a per-release impact decision with its justification.
type ReleaseTriage struct {
	Status        ImpactStatus `json:"status,omitempty"`
	Justification string       `json:"justification,omitempty"`
}

// IsEmpty returns true if the release triage has no status set.
func (t ReleaseTriage) IsEmpty() bool {
	return t.Status == ImpactUnknown
}

// ReleaseDecision holds the automatic and manual impact decisions for a specific GL release.
type ReleaseDecision struct {
	AutoTriage     ReleaseTriage `json:"auto_triage,omitzero"      merge:"overwrite"`
	PackageVersion string        `json:"package_version,omitempty" merge:"overwrite"`
	FixAvailable   bool          `json:"fix_available,omitempty"   merge:"overwrite"`
	DebianStatus   string        `json:"debian_status,omitempty"   merge:"overwrite"`
	ManualTriage   ReleaseTriage `json:"manual_triage,omitzero"    merge:"preserve"`
}

// GetGlobalStatus returns the effective triage status (manual overrides auto).
func (r Record) GetGlobalStatus() TriageStatus {
	if r.Manual.ManualTriage.Status != StatusUndecided {
		return r.Manual.ManualTriage.Status
	}

	return r.Screening.AutoTriage.Status()
}

// GetReleaseStatus returns the impact status for a specific release.
// Manual overrides auto at the per-release level.
func (r Record) GetReleaseStatus(release string) ImpactStatus {
	if rd, ok := r.Releases[release]; ok {
		if rd.ManualTriage.Status != ImpactUnknown {
			return rd.ManualTriage.Status
		}
		if rd.AutoTriage.Status != ImpactUnknown {
			return rd.AutoTriage.Status
		}
	}

	return ImpactUnknown
}
