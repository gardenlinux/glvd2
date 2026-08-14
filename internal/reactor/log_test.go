package reactor_test

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/gardenlinux/glvd2/internal/reactor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Verify that Log satisfies the Reactor interface.
var _ assessment.Reactor = reactor.Log{}

func newTestLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

func TestLog_React_NoChanges(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	r := reactor.Log{Logger: newTestLogger(&buf)}
	old := assessment.Record{ID: "CVE-2025-1000"}
	rec := &assessment.Record{ID: "CVE-2025-1000"}
	cs := assessment.ChangeSet{CVEID: "CVE-2025-1000", Type: assessment.Unchanged}

	err := r.React(t.Context(), old, rec, cs)
	require.NoError(t, err)
	assert.Empty(t, buf.String())
}

func TestLog_React_Created(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	r := reactor.Log{Logger: newTestLogger(&buf)}
	old := assessment.Record{ID: "CVE-2025-2000"}
	rec := &assessment.Record{
		ID: "CVE-2025-2000",
		Screening: assessment.ScreeningResult{
			AutoTriage: assessment.Triage{Status: assessment.StatusRelevant, Justification: "affects foo"},
		},
	}
	cs := assessment.ChangeSet{
		CVEID: "CVE-2025-2000",
		Type:  assessment.Created,
		Changes: []assessment.FieldChange{
			{Field: assessment.FieldPath{"upstream", "description"}, OldValue: "", NewValue: "buffer overflow in foo"},
			{Field: assessment.FieldPath{"screening", "auto_triage", "status"}, OldValue: "", NewValue: "relevant"},
		},
	}

	err := r.React(t.Context(), old, rec, cs)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "CVE-2025-2000")
	assert.Contains(t, output, "created")
	assert.Contains(t, output, "cve assessment record changed")
}

func TestLog_React_Updated(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	r := reactor.Log{Logger: newTestLogger(&buf)}
	old := assessment.Record{
		ID: "CVE-2025-3000",
		Screening: assessment.ScreeningResult{
			AutoTriage: assessment.Triage{Status: assessment.StatusRelevant, Justification: "old reason"},
		},
	}
	rec := &assessment.Record{
		ID: "CVE-2025-3000",
		Screening: assessment.ScreeningResult{
			AutoTriage: assessment.Triage{Status: assessment.StatusCritical, Justification: "CVSS bumped"},
		},
	}
	cs := assessment.ChangeSet{
		CVEID: "CVE-2025-3000",
		Type:  assessment.Updated,
		Changes: []assessment.FieldChange{
			{
				Field:    assessment.FieldPath{"screening", "auto_triage", "status"},
				OldValue: "relevant",
				NewValue: "critical",
			},
		},
	}

	err := r.React(t.Context(), old, rec, cs)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "CVE-2025-3000")
	assert.Contains(t, output, "updated")
	assert.Contains(t, output, "critical")
}

func TestLog_React_NilLoggerFallsBackToDefault(t *testing.T) {
	t.Parallel()

	r := reactor.Log{} // nil logger
	old := assessment.Record{ID: "CVE-2025-4000"}
	rec := &assessment.Record{ID: "CVE-2025-4000"}
	cs := assessment.ChangeSet{
		CVEID: "CVE-2025-4000",
		Type:  assessment.Created,
		Changes: []assessment.FieldChange{
			{Field: assessment.FieldPath{"upstream", "description"}, NewValue: "test"},
		},
	}

	// Should not panic.
	err := r.React(t.Context(), old, rec, cs)
	require.NoError(t, err)
}
