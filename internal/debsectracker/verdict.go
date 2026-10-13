package debsectracker

import "strings"

// Status is the coarse status a [Verdict] derives from its [Reason].
type Status string

const (
	// StatusUndecided means no usable signal was present.
	StatusUndecided Status = "undecided"
	// StatusFixed means the sid line names a concrete fixed version (vulnerable below it).
	StatusFixed Status = "fixed"
	// StatusNotAffected means Debian marks the package not vulnerable.
	StatusNotAffected Status = "not-affected"
	// StatusAffectedNoFix means Debian marks the package affected but names no fix version.
	StatusAffectedNoFix Status = "affected-no-fix"
)

// Reason is the specific Security Tracker sid-line cause behind a [Verdict].
// It is the single source of truth, from which [Verdict.Status] is derived.
type Reason string

const (
	// ReasonFixed - the sid line names a concrete fixed version.
	ReasonFixed Reason = "fixed"
	// ReasonNotAffected - <not-affected>.
	ReasonNotAffected Reason = "not-affected"
	// ReasonUnfixed - <unfixed>: affected, no fix.
	ReasonUnfixed Reason = "unfixed"
	// ReasonEndOfLife - <end-of-life>: affected, suite EOL, will not be fixed.
	ReasonEndOfLife Reason = "end-of-life"
	// ReasonITP - <itp>: intent-to-package, not in Debian yet.
	ReasonITP Reason = "itp"
	// ReasonRemoved - <removed>: removed from Debian.
	ReasonRemoved Reason = "removed"
	// ReasonUndetermined - <undetermined>: Debian has not decided.
	ReasonUndetermined Reason = "undetermined"
	// ReasonUnknownToken - an unrecognised <...> token (or an unexpected empty field).
	ReasonUnknownToken Reason = "unknown-token"
	// ReasonNoEntry - the source has no sid line for this CVE.
	ReasonNoEntry Reason = "no-entry"
)

// Verdict is the per-(CVE, source pkg name) DST verdict.
type Verdict struct {
	// Reason is the sid-line cause and the single source of truth for the status.
	Reason Reason
	// FixedVersion is the sid fixed version, set only when Reason is [ReasonFixed].
	FixedVersion string
	// Info is Debian's free-text annotation from the sid line.
	Info string
}

// Status derives the coarse status from the verdict's reason.
func (v Verdict) Status() Status {
	switch v.Reason {
	case ReasonFixed:
		return StatusFixed
	case ReasonNotAffected:
		return StatusNotAffected
	case ReasonUnfixed, ReasonEndOfLife:
		return StatusAffectedNoFix
	case ReasonITP, ReasonRemoved, ReasonUndetermined, ReasonUnknownToken, ReasonNoEntry:
		return StatusUndecided
	}

	return StatusUndecided
}

// VerdictFromSid maps the version field of a DST unstable/sid line to a [Verdict].
//
// Garden Linux tracks Debian testing, but the DST only tracks unstable/sid not testing.
// Hence, we use the sid entry as a conservative upper bound for the state of testing.
// This could result in over-reporting releases to be affected, but never under-reporting them.
func VerdictFromSid(sidVersion, info string) Verdict {
	v := Verdict{Info: info}

	switch {
	case sidVersion == "":
		v.Reason = ReasonUnknownToken
	case !strings.HasPrefix(sidVersion, "<"):
		v.Reason = ReasonFixed
		v.FixedVersion = sidVersion
	default:
		v.Reason = reasonFromVersionToken(sidVersion)
	}

	return v
}

// DST's version field can contain tokens that indicate different triage reasons than a fixed version present.
const (
	sidNotAffected  = "<not-affected>"
	sidUnfixed      = "<unfixed>"
	sidEndOfLife    = "<end-of-life>"
	sidITP          = "<itp>"
	sidRemoved      = "<removed>"
	sidUndetermined = "<undetermined>"
)

func reasonFromVersionToken(token string) Reason {
	switch token {
	case sidNotAffected:
		return ReasonNotAffected
	case sidUnfixed:
		return ReasonUnfixed
	case sidEndOfLife:
		return ReasonEndOfLife
	case sidITP:
		return ReasonITP
	case sidRemoved:
		return ReasonRemoved
	case sidUndetermined:
		return ReasonUndetermined
	default:
		return ReasonUnknownToken
	}
}
