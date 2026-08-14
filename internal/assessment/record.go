package assessment

import "time"

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
	AutoTriage    Triage  `json:"auto_triage,omitzero"`
	Matches       Matches `json:"matches,omitzero"`
	PriorityScore float64 `json:"priority_score,omitempty"`
}

// Matches holds which CPEs and packages were matched to this CVE.
type Matches struct {
	CPEs     []string `json:"cpes,omitempty"`
	Packages []string `json:"packages,omitempty"`
}

// ManualOverride is human-provided data - never touched by the program.
type ManualOverride struct {
	ManualTriage Triage `json:"manual_triage,omitzero"`
	Notes        string `json:"notes,omitempty"`
}

// Metadata is set once as a side effect and preserved across runs.
type Metadata struct {
	IssueNumber int       `json:"issue_number,omitempty"`
	FirstSeenAt time.Time `json:"first_seen_at,omitzero"`
}

// TriageStatus represents the global triage decision for a CVE's relevance to Garden Linux.
type TriageStatus string

const (
	// StatusUndecided means no decision has been made yet (needs human triage).
	StatusUndecided TriageStatus = ""
	// StatusRelevant means the CVE affects Garden Linux and needs attention.
	StatusRelevant TriageStatus = "relevant"
	// StatusNotRelevant means the CVE does not affect Garden Linux.
	StatusNotRelevant TriageStatus = "not-relevant"
	// StatusCritical means the CVE urgently affects Garden Linux.
	StatusCritical TriageStatus = "critical"
	// StatusLowPriority means the CVE affects Garden Linux but with low impact.
	StatusLowPriority TriageStatus = "low-priority"
)

// Triage holds a triage decision with its justification.
type Triage struct {
	Status        TriageStatus `json:"status,omitempty"`
	Justification string       `json:"justification,omitempty"`
}

// IsEmpty returns true if the triage has no status set.
func (t Triage) IsEmpty() bool {
	return t.Status == StatusUndecided
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

// GetGlobalStatus returns the global triage decision (manual overrides auto).
func (r Record) GetGlobalStatus() TriageStatus {
	if r.Manual.ManualTriage.Status != StatusUndecided {
		return r.Manual.ManualTriage.Status
	}

	return r.Screening.AutoTriage.Status
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
