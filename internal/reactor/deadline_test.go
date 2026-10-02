package reactor_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/gardenlinux/glvd2/internal/pkgsuggest"
	"github.com/gardenlinux/glvd2/internal/reactor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Verify that DebianVerdictDeadline satisfies the Reactor interface.
var _ assessment.Reactor = reactor.DebianVerdictDeadline{}

// fakeSuggester returns fixed candidates regardless of CVE ID.
type fakeSuggester struct {
	candidates []pkgsuggest.Candidate
}

func (f fakeSuggester) Suggest(_ string) []pkgsuggest.Candidate { return f.candidates }

func undecidedRecord(id string, firstSeen time.Time) *assessment.Record {
	return &assessment.Record{
		ID: id,
		Screening: assessment.ScreeningResult{
			AutoTriage: assessment.AutoTriage{Reason: assessment.TriageReasonAwaitingDebian},
		},
		Meta: assessment.Metadata{FirstSeenAt: firstSeen},
	}
}

// runReact drives the reactor and returns the single captured log record.
func runReact(t *testing.T, r reactor.DebianVerdictDeadline, rec *assessment.Record) map[string]any {
	t.Helper()

	var buf bytes.Buffer
	r.Logger = slog.New(slog.NewJSONHandler(&buf, nil))

	require.NoError(t, r.React(context.Background(), assessment.Record{}, rec, assessment.ChangeSet{}))

	if buf.Len() == 0 {
		return nil
	}

	var output map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &output))

	return output
}

func TestDebianVerdictDeadline_Kind(t *testing.T) {
	t.Parallel()

	assert.Equal(t, assessment.ReactorKindAlways, reactor.DebianVerdictDeadline{}.Kind())
}

func TestDebianVerdictDeadline_EscalationDecision(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	past := now.Add(-48 * time.Hour)
	const window = 24 * time.Hour

	cases := []struct {
		name         string
		rec          *assessment.Record
		wantEscalate bool
	}{
		{
			name:         "within window",
			rec:          undecidedRecord("CVE-2026-1", now.Add(-1*time.Hour)),
			wantEscalate: false,
		},
		{
			name:         "past window",
			rec:          undecidedRecord("CVE-2026-1", now.Add(-25*time.Hour)),
			wantEscalate: true,
		},
		{
			name:         "exactly at window",
			rec:          undecidedRecord("CVE-2026-1", now.Add(-window)),
			wantEscalate: true,
		},
		{
			name: "already decided",
			rec: &assessment.Record{
				ID: "CVE-2026-3",
				Screening: assessment.ScreeningResult{
					AutoTriage: assessment.AutoTriage{Reason: assessment.TriageReasonAffectsDebianPackage},
				},
				Meta: assessment.Metadata{FirstSeenAt: past},
			},
			wantEscalate: false,
		},
		{
			name: "manual override set",
			rec: &assessment.Record{
				ID: "CVE-2026-4",
				Screening: assessment.ScreeningResult{
					AutoTriage: assessment.AutoTriage{Reason: assessment.TriageReasonAwaitingDebian},
				},
				Manual: assessment.ManualOverride{
					ManualTriage: assessment.ManualTriage{Status: assessment.StatusNotRelevant},
				},
				Meta: assessment.Metadata{FirstSeenAt: past},
			},
			wantEscalate: false,
		},
		{
			name: "screening not run (empty reason)",
			rec: &assessment.Record{
				ID:   "CVE-2026-6",
				Meta: assessment.Metadata{FirstSeenAt: past},
			},
			wantEscalate: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := reactor.DebianVerdictDeadline{Now: func() time.Time { return now }, TimeToWait: window}
			output := runReact(t, r, tc.rec)

			if !tc.wantEscalate {
				assert.Nil(t, output)
				return
			}

			require.NotNil(t, output)
			assert.Equal(t, tc.rec.ID, output["cve_id"])
		})
	}
}

func TestDebianVerdictDeadline_EscalationCarriesAgeAndCandidates(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	candidates := []pkgsuggest.Candidate{
		{
			PackageName: "pkg:deb/debian/openssl",
			Matches: []pkgsuggest.Match{
				{Identifier: "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*", Count: 9},
			},
		},
	}
	r := reactor.DebianVerdictDeadline{
		Now:        func() time.Time { return now },
		TimeToWait: 24 * time.Hour,
		Suggester:  fakeSuggester{candidates: candidates},
	}

	rec := undecidedRecord("CVE-2026-2", now.Add(-25*time.Hour))
	output := runReact(t, r, rec)

	require.NotNil(t, output)
	assert.Equal(t, "CVE-2026-2", output["cve_id"])
	assert.EqualValues(t, (25 * time.Hour).Nanoseconds(), output["age"])

	cands, ok := output["candidates"].(map[string]any)
	require.True(t, ok, "candidates group present")
	first, ok := cands["0"].(map[string]any)
	require.True(t, ok, "first candidate present")
	assert.Equal(t, "pkg:deb/debian/openssl", first["package"])
}

func TestDebianVerdictDeadline_React_MissingFirstSeenAtTimestamp_WarnsButDoesNotEscalate(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 20, 11, 12, 10, 123, time.UTC)
	r := reactor.DebianVerdictDeadline{Now: func() time.Time { return now }, TimeToWait: 24 * time.Hour}

	// Awaiting a Debian verdict but with no FirstSeenAt timestamp, it cannot be calculated.
	rec := &assessment.Record{
		ID: "CVE-2026-5",
		Screening: assessment.ScreeningResult{
			AutoTriage: assessment.AutoTriage{Reason: assessment.TriageReasonAwaitingDebian},
		},
	}

	output := runReact(t, r, rec)

	require.NotNil(t, output, "missing FirstSeenAt timestamp error must not be silent")
	assert.Equal(t, "WARN", output["level"])
	assert.Equal(t, "CVE-2026-5", output["cve_id"])
	assert.NotContains(t, output, "candidates", "must not escalate")
}
