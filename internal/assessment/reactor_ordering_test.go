package assessment_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/gardenlinux/glvd2/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingReactor records how often it ran and reports a configurable kind.
type countingReactor struct {
	kind  assessment.ReactorKind
	calls *int
}

func (r countingReactor) Kind() assessment.ReactorKind { return r.kind }

func (r countingReactor) React(
	_ context.Context,
	_ assessment.Record,
	_ *assessment.Record,
	_ assessment.ChangeSet,
) error {
	*r.calls++

	return nil
}

// newTestServiceWithReactors mirrors newTestService but wires custom reactors.
func newTestServiceWithReactors(
	ctx context.Context,
	t *testing.T,
	store *assessment.Store,
	dir string,
	reactors []assessment.Reactor,
	baselineRecs ...assessment.Record,
) *assessment.Service {
	t.Helper()

	const sha = "baselinecommit"

	showFiles := make(map[string][]byte)
	for _, rec := range baselineRecs {
		p, err := assessment.Path(dir, rec.ID)
		require.NoError(t, err)
		data, err := json.Marshal(rec)
		require.NoError(t, err)
		showFiles[sha+":"+p] = data
	}

	commitSHA := ""
	if len(showFiles) > 0 {
		commitSHA = sha
	}

	gitReader := &serviceTestGitReader{commitSHA: commitSHA, showFiles: showFiles}
	baseline, err := assessment.NewBaseline(ctx, gitReader, testServiceConfig(dir))
	require.NoError(t, err)

	s, err := assessment.NewService(ctx, store, baseline, reactors)
	require.NoError(t, err)

	return s
}

// TestServiceProcess_ReactorKindOrdering verifies that on an empty diff the always-reactor
// still fires while the change-reactor does not, and that on a real change both fire.
func TestServiceProcess_ReactorKindOrdering(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := assessment.NewStore(&config.AppConfig{AssessmentsDir: dir})
	ctx := t.Context()

	rec := assessment.Record{
		ID:       "CVE-2025-1000",
		Upstream: assessment.UpstreamData{Description: "Some vuln."},
	}
	require.NoError(t, store.Save(rec))

	var alwaysCalls, changeCalls int
	reactors := []assessment.Reactor{
		countingReactor{kind: assessment.ReactorKindAlways, calls: &alwaysCalls},
		countingReactor{kind: assessment.ReactorKindChange, calls: &changeCalls},
	}

	// Empty diff: process the record against itself as baseline.
	s := newTestServiceWithReactors(ctx, t, store, dir, reactors, rec)
	_, cs, err := s.Process(ctx, rec)
	require.NoError(t, err)
	require.Equal(t, assessment.Unchanged, cs.Type)

	assert.Equal(t, 1, alwaysCalls, "always-reactor must fire on an empty diff")
	assert.Equal(t, 0, changeCalls, "change-reactor must not fire on an empty diff")

	// Real change: updated description relative to the seeded baseline.
	changed := rec
	changed.Upstream.Description = "Updated vuln."
	_, cs, err = s.Process(ctx, changed)
	require.NoError(t, err)
	require.Equal(t, assessment.Updated, cs.Type)

	assert.Equal(t, 2, alwaysCalls, "always-reactor must fire again on a real change")
	assert.Equal(t, 1, changeCalls, "change-reactor must fire on a real change")
}

// TestServiceProcess_SelfHealFlipFiresChangeReactor covers the case where a CVE screened
// not-relevant flips to relevant on a later run.
func TestServiceProcess_SelfHealFlipFiresChangeReactor(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := assessment.NewStore(&config.AppConfig{AssessmentsDir: dir})
	ctx := t.Context()

	// Day 1: screened not-relevant (Debian NOT-FOR-US).
	baseline := assessment.Record{
		ID: "CVE-2025-2000",
		Screening: assessment.ScreeningResult{
			AutoTriage: assessment.AutoTriage{Reason: assessment.TriageReasonDebianNotForUs},
		},
	}
	require.NoError(t, store.Save(baseline))

	var changeCalls int
	reactors := []assessment.Reactor{
		countingReactor{kind: assessment.ReactorKindChange, calls: &changeCalls},
	}
	s := newTestServiceWithReactors(ctx, t, store, dir, reactors, baseline)

	incoming := assessment.Record{
		ID: "CVE-2025-2000",
		Screening: assessment.ScreeningResult{
			AutoTriage: assessment.AutoTriage{Reason: assessment.TriageReasonAffectsGardenLinuxPackage},
		},
	}
	merged, cs, err := s.Process(ctx, incoming)
	require.NoError(t, err)

	assert.Equal(t, assessment.Updated, cs.Type)
	assert.Equal(t, assessment.StatusRelevant, merged.GetGlobalStatus())
	assert.Equal(t, 1, changeCalls, "the flip must fire the change-reactor")
}
