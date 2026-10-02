package reactor

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/gardenlinux/glvd2/internal/pkgsuggest"
)

// DebianVerdictDeadline is an always-reactor that escalates a CVE to human triage
// once we have waited too long for Debian to reach a verdict.
type DebianVerdictDeadline struct {
	// Now returns the current time; defaults to time.Now().UTC() when nil (injectable for tests).
	Now func() time.Time
	// TimeToWait is how long we wait for a Debian verdict before escalating.
	TimeToWait time.Duration
	// Suggester attaches candidate packages to the escalation.
	Suggester CandidateSuggester
	// Logger is used to log the escalation; defaults to slog.Default() when nil.
	Logger *slog.Logger
}

// Kind is used to mark this as always reactor that triggers always even for empty diffs.
func (DebianVerdictDeadline) Kind() assessment.ReactorKind { return assessment.ReactorKindAlways }

func (r DebianVerdictDeadline) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}

	return time.Now().UTC()
}

func (r DebianVerdictDeadline) logger() *slog.Logger {
	if r.Logger != nil {
		return r.Logger
	}

	return slog.Default()
}

// CandidateSuggester ranks advisory Debian package candidates for a CVE by its identifiers.
type CandidateSuggester interface {
	Suggest(cveID string) []pkgsuggest.Candidate
}

// React escalates the CVE when the wait time for a Debian verdict has elapsed.
func (r DebianVerdictDeadline) React(
	ctx context.Context,
	_ assessment.Record,
	updated *assessment.Record,
	_ assessment.ChangeSet,
) error {
	// Only act while awaiting a Debian verdict (not for undecided or potential manual overrides).
	if updated.GetGlobalStatus() != assessment.StatusUndecided ||
		updated.Screening.AutoTriage.Reason != assessment.TriageReasonAwaitingDebian {
		return nil
	}

	// FirstSeenAt is seeded on first ingestion; it should be defined here, log otherwise just to be sure.
	if updated.Meta.FirstSeenAt.IsZero() {
		r.logger().WarnContext(ctx, "awaiting-debian CVE has no FirstSeenAt timestamp! not escalating",
			slog.String("cve_id", updated.ID))
		return nil
	}

	age := r.now().Sub(updated.Meta.FirstSeenAt)
	if age < r.TimeToWait {
		return nil // still waiting
	}

	esc := escalation{cveID: updated.ID, age: age}
	if r.Suggester != nil {
		esc.candidates = r.Suggester.Suggest(esc.cveID)
	}

	r.act(ctx, esc)

	return nil
}

// escalation carries the facts about a CVE that has exceeded its wait window.
type escalation struct {
	cveID string
	// age is how long the CVE has been undecided (now - FirstSeenAt) at escalation time.
	age time.Duration
	// candidates are advisory-only ranked Debian package suggestions. They enrich the
	// human-triage handoff but never change the decision.
	candidates []pkgsuggest.Candidate
}

func (r DebianVerdictDeadline) act(ctx context.Context, esc escalation) {
	candidateAttrs := make([]slog.Attr, 0, len(esc.candidates))
	for i, c := range esc.candidates {
		matchAttrs := make([]any, 0, len(c.Matches))
		for j, m := range c.Matches {
			matchAttrs = append(matchAttrs, slog.Group(strconv.Itoa(j),
				slog.String("identifier", m.Identifier),
				slog.Int("count", m.Count),
			))
		}
		candidateAttrs = append(candidateAttrs, slog.Group(strconv.Itoa(i),
			slog.String("package", c.PackageName),
			slog.Group("matches", matchAttrs...),
		))
	}

	r.logger().LogAttrs(ctx, slog.LevelInfo, "would escalate undecided CVE to human triage (stub)",
		slog.String("cve_id", esc.cveID),
		slog.Duration("age", esc.age),
		slog.Int("candidate_count", len(esc.candidates)),
		slog.Attr{Key: "candidates", Value: slog.GroupValue(candidateAttrs...)},
	)
}
