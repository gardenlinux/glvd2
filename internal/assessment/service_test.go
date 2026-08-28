package assessment_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/gardenlinux/glvd2/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// serviceTestGitReader is a fake GitReader.
// commitSHA controls what FindCommitByMessageAnchor returns:
//   - empty string → first run (no previous program commit)
//   - non-empty string → that SHA is returned as the last program commit
//
// showFiles maps "commit:path" to content for ShowFileAtCommit lookups.
// DiffFilesSince returns the path portion of every key whose commit prefix
// matches the requested SHA.
type serviceTestGitReader struct {
	commitSHA string
	// showFiles maps "commit:path" to content for baseline lookups.
	showFiles map[string][]byte
}

func (f *serviceTestGitReader) FindCommitByMessageAnchor(_ context.Context, _ string) (string, error) {
	return f.commitSHA, nil
}

func (f *serviceTestGitReader) DiffFilesSince(_ context.Context, commitSHA, _ string) ([]string, error) {
	// Report all files whose key starts with "<commitSHA>:" as externally modified.
	prefix := commitSHA + ":"
	var files []string
	for key := range f.showFiles {
		if _, path, ok := strings.Cut(key, ":"); ok && strings.HasPrefix(key, prefix) {
			files = append(files, path)
		}
	}
	return files, nil
}

func (f *serviceTestGitReader) ShowFileAtCommit(_ context.Context, commitSHA, filePath string) ([]byte, error) {
	key := commitSHA + ":" + filePath
	content, ok := f.showFiles[key]
	if !ok {
		return nil, nil
	}
	return content, nil
}

func testServiceConfig(dir string) *config.AppConfig {
	return &config.AppConfig{
		AssessmentsDir:       dir,
		BaselineCommitAnchor: "GLVD2-Baseline: true",
	}
}

// newTestService creates a Service backed by a fake GitReader with the given baseline assessments.
func newTestService(
	ctx context.Context,
	t *testing.T,
	store *assessment.Store,
	dir string,
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
	cfg := testServiceConfig(dir)
	baseline, err := assessment.NewBaseline(ctx, gitReader, cfg)
	require.NoError(t, err)

	s, err := assessment.NewService(ctx, store, baseline, nil)
	require.NoError(t, err)
	return s
}

func TestServiceProcess_Overwrites(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := assessment.NewStore(&config.AppConfig{AssessmentsDir: dir})
	ctx := t.Context()

	rec := assessment.Record{
		ID: "CVE-2025-1000",
		Upstream: assessment.UpstreamData{
			Description: "Original description.",
		},
	}

	// Seed the store.
	require.NoError(t, store.Save(rec))

	// Process with updated description
	baseline := rec
	rec.Upstream.Description = "Updated description."
	s := newTestService(ctx, t, store, dir, baseline)

	merged, cs, err := s.Process(ctx, rec)
	require.NoError(t, err)

	assert.Equal(t, "Updated description.", merged.Upstream.Description)

	assert.Equal(t, assessment.Updated, cs.Type)
	assert.True(t, cs.HasChanges())
	changeMap := make(map[string]assessment.FieldChange)
	for _, c := range cs.Changes {
		changeMap[c.Field.String()] = c
	}
	assert.Contains(t, changeMap, "upstream.description")
	assert.Equal(t, "Original description.", changeMap["upstream.description"].OldValue)
	assert.Equal(t, "Updated description.", changeMap["upstream.description"].NewValue)

	// Verify the store was also updated.
	got, err := store.Get("CVE-2025-1000")
	require.NoError(t, err)
	assert.Equal(t, "Updated description.", got.Upstream.Description)
}

func TestServiceProcess_NewRecord(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := assessment.NewStore(&config.AppConfig{AssessmentsDir: dir})
	ctx := t.Context()

	// No baseline records; treat it as first run.
	s := newTestService(ctx, t, store, dir)

	incoming := assessment.Record{
		ID: "CVE-2025-5000",
		Upstream: assessment.UpstreamData{
			Description: "New vulnerability.",
		},
		Screening: assessment.ScreeningResult{
			AutoTriage: assessment.Triage{Status: assessment.StatusRelevant, Justification: "affects bar"},
		},
		Releases: map[string]assessment.ReleaseDecision{
			"2150.8.0": {
				AutoTriage: assessment.ReleaseTriage{
					Status: assessment.ImpactAffected, Justification: "ships bar 2.0",
				},
			},
		},
	}

	merged, cs, err := s.Process(ctx, incoming)
	require.NoError(t, err)

	assert.Equal(t, incoming, merged)
	assert.Equal(t, assessment.Created, cs.Type)
	assert.True(t, cs.HasChanges())
}

func TestServiceProcess_PreservesManual(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := assessment.NewStore(&config.AppConfig{AssessmentsDir: dir})
	ctx := t.Context()

	// Seed an existing record with manual fields.
	existing := assessment.Record{
		ID: "CVE-2025-6000",
		Upstream: assessment.UpstreamData{
			Description: "Old description.",
		},
		Screening: assessment.ScreeningResult{
			AutoTriage: assessment.Triage{Status: assessment.StatusRelevant, Justification: "old reason"},
		},
		Manual: assessment.ManualOverride{
			ManualTriage: assessment.Triage{
				Status: assessment.StatusNotRelevant, Justification: "human says no",
			},
			Notes: "reviewed in sprint 42",
		},
		Meta: assessment.Metadata{
			IssueNumber: 42,
		},
		Releases: map[string]assessment.ReleaseDecision{
			"2150.8.0": {
				AutoTriage: assessment.ReleaseTriage{
					Status: assessment.ImpactAffected, Justification: "old",
				},
				ManualTriage: assessment.ReleaseTriage{
					Status: assessment.ImpactNotAffected, Justification: "DTLS disabled",
				},
			},
		},
	}
	require.NoError(t, store.Save(existing))

	// Incoming only provides overwrite fields.
	incoming := assessment.Record{
		ID: "CVE-2025-6000",
		Upstream: assessment.UpstreamData{
			Description: "Updated description.",
		},
		Screening: assessment.ScreeningResult{
			AutoTriage: assessment.Triage{Status: assessment.StatusCritical, Justification: "CVSS bumped"},
		},
		Releases: map[string]assessment.ReleaseDecision{
			"2150.8.0": {
				AutoTriage: assessment.ReleaseTriage{
					Status: assessment.ImpactAffected, Justification: "still affected",
				},
			},
		},
	}

	s := newTestService(ctx, t, store, dir, existing)
	merged, cs, err := s.Process(ctx, incoming)
	require.NoError(t, err)

	// Overwrite: overwritten.
	assert.Equal(t, "Updated description.", merged.Upstream.Description)
	assert.Equal(t, assessment.StatusCritical, merged.Screening.AutoTriage.Status)
	assert.Equal(t, "CVSS bumped", merged.Screening.AutoTriage.Justification)
	// Preserve: preserved.
	assert.Equal(t, assessment.StatusNotRelevant, merged.Manual.ManualTriage.Status)
	assert.Equal(t, "human says no", merged.Manual.ManualTriage.Justification)
	assert.Equal(t, "reviewed in sprint 42", merged.Manual.Notes)
	assert.Equal(t, 42, merged.Meta.IssueNumber)
	// Per-release overwrite: overwritten.
	assert.Equal(t, assessment.ImpactAffected, merged.Releases["2150.8.0"].AutoTriage.Status)
	assert.Equal(t, "still affected", merged.Releases["2150.8.0"].AutoTriage.Justification)
	// Per-release preserve: preserved.
	assert.Equal(t, assessment.ImpactNotAffected, merged.Releases["2150.8.0"].ManualTriage.Status)
	assert.Equal(t, "DTLS disabled", merged.Releases["2150.8.0"].ManualTriage.Justification)

	// ChangeSet reflects updates.
	assert.Equal(t, assessment.Updated, cs.Type)
	assert.True(t, cs.HasChanges())
}

func TestServiceProcess_PreservesEOLReleases(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	dir := t.TempDir()
	store := assessment.NewStore(&config.AppConfig{AssessmentsDir: dir})

	// Existing record has an old release.
	existing := assessment.Record{
		ID: "CVE-2025-7000",
		Upstream: assessment.UpstreamData{
			Description: "Some vuln.",
		},
		Releases: map[string]assessment.ReleaseDecision{
			"1592.2": { // older releases had a different format
				AutoTriage: assessment.ReleaseTriage{
					Status: assessment.ImpactAffected, Justification: "EOL release",
				},
			},
			"2150.8.0": {
				AutoTriage: assessment.ReleaseTriage{
					Status: assessment.ImpactAffected, Justification: "current",
				},
			},
		},
	}
	require.NoError(t, store.Save(existing))

	// Incoming only updates active releases (2150), doesn't mention 1580.
	incoming := assessment.Record{
		ID: "CVE-2025-7000",
		Upstream: assessment.UpstreamData{
			Description: "Some vuln.",
		},
		Releases: map[string]assessment.ReleaseDecision{
			"2150.8.0": {
				AutoTriage: assessment.ReleaseTriage{
					Status: assessment.ImpactFixed, Justification: "patched",
				},
			},
		},
	}

	s := newTestService(ctx, t, store, dir, existing)
	merged, cs, err := s.Process(ctx, incoming)
	require.NoError(t, err)

	// EOL release preserved (map,preserve semantics).
	assert.Equal(t, assessment.ImpactAffected, merged.Releases["1592.2"].AutoTriage.Status)
	// Active release updated.
	assert.Equal(t, assessment.ImpactFixed, merged.Releases["2150.8.0"].AutoTriage.Status)

	assert.Equal(t, assessment.Updated, cs.Type)
	assert.True(t, cs.HasChanges())
	changeMap := make(map[string]assessment.FieldChange)
	for _, c := range cs.Changes {
		changeMap[c.Field.String()] = c
	}
	assert.Contains(t, changeMap, "releases.2150.8.0.auto_triage.status")
	assert.Equal(t, "affected", changeMap["releases.2150.8.0.auto_triage.status"].OldValue)
	assert.Equal(t, "fixed", changeMap["releases.2150.8.0.auto_triage.status"].NewValue)
}

// TestDiff_BotEditDetected_Integration tests the full pipeline scenario where
// the bot edits a file on disk between program runs.
func TestDiff_BotEditDetected_Integration(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := assessment.NewStore(&config.AppConfig{AssessmentsDir: dir})
	ctx := t.Context()

	baseline := assessment.Record{
		ID: "CVE-2025-6002",
		Screening: assessment.ScreeningResult{
			AutoTriage: assessment.Triage{Status: assessment.StatusRelevant, Justification: "reason"},
		},
		Releases: map[string]assessment.ReleaseDecision{
			"2150.8.0": {
				AutoTriage: assessment.ReleaseTriage{
					Status: assessment.ImpactAffected, Justification: "ships it",
				},
			},
		},
	}

	// Simulate bot editing the file on disk directly.
	botEdited := assessment.Record{
		ID: "CVE-2025-6002",
		Screening: assessment.ScreeningResult{
			AutoTriage: assessment.Triage{Status: assessment.StatusRelevant, Justification: "reason"},
		},
		Manual: assessment.ManualOverride{
			ManualTriage: assessment.Triage{
				Status: assessment.StatusNotRelevant, Justification: "human decided",
			},
		},
		Releases: map[string]assessment.ReleaseDecision{
			"2150.8.0": {
				AutoTriage: assessment.ReleaseTriage{
					Status: assessment.ImpactAffected, Justification: "ships it",
				},
				ManualTriage: assessment.ReleaseTriage{
					Status: assessment.ImpactNotAffected, Justification: "disabled",
				},
			},
		},
	}
	require.NoError(t, store.Save(botEdited))

	// Program runs with unchanged computed data.
	incoming := assessment.Record{
		ID: "CVE-2025-6002",
		Screening: assessment.ScreeningResult{
			AutoTriage: assessment.Triage{Status: assessment.StatusRelevant, Justification: "reason"},
		},
		Releases: map[string]assessment.ReleaseDecision{
			"2150.8.0": {
				AutoTriage: assessment.ReleaseTriage{
					Status: assessment.ImpactAffected, Justification: "ships it",
				},
			},
		},
	}

	s := newTestService(ctx, t, store, dir, baseline)
	merged, cs, err := s.Process(ctx, incoming)
	require.NoError(t, err)

	assert.Equal(t, assessment.Updated, cs.Type)
	assert.True(t, cs.HasChanges())

	changeMap := make(map[string]assessment.FieldChange)
	for _, c := range cs.Changes {
		changeMap[c.Field.String()] = c
	}

	assert.Contains(t, changeMap, "manual.manual_triage.status")
	assert.Empty(t, changeMap["manual.manual_triage.status"].OldValue)
	assert.Equal(t, "not-relevant", changeMap["manual.manual_triage.status"].NewValue)

	assert.Contains(t, changeMap, "releases.2150.8.0.manual_triage.status")
	assert.Empty(t, changeMap["releases.2150.8.0.manual_triage.status"].OldValue)
	assert.Equal(t, "not-affected", changeMap["releases.2150.8.0.manual_triage.status"].NewValue)

	// Bot edits must be preserved in the final merged result.
	assert.Equal(t, assessment.StatusNotRelevant, merged.Manual.ManualTriage.Status)
	assert.Equal(t, "human decided", merged.Manual.ManualTriage.Justification)
	assert.Equal(t, assessment.ImpactNotAffected, merged.Releases["2150.8.0"].ManualTriage.Status)
	assert.Equal(t, "disabled", merged.Releases["2150.8.0"].ManualTriage.Justification)
}

// TestServiceProcess_CommittedOverwriteBotEdit checks that external edits to program-owned (overwrite)
// fields are not ignored and will be overwritten to ensure that the state on disk is consistent.
func TestServiceProcess_CommittedOverwriteBotEdit(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := assessment.NewStore(&config.AppConfig{AssessmentsDir: dir})
	ctx := t.Context()

	const originalDesc = "Original description."
	const botDesc = "Bot changed this."

	baseline := assessment.Record{
		ID: "CVE-2025-9100",
		Upstream: assessment.UpstreamData{
			Description: originalDesc,
		},
	}

	// bot committed a change to an overwrite field directly on disk.
	botEdited := assessment.Record{
		ID: "CVE-2025-9100",
		Upstream: assessment.UpstreamData{
			Description: botDesc,
		},
	}
	require.NoError(t, store.Save(botEdited))

	// Incoming (computed) still has the original value.
	incoming := assessment.Record{
		ID: "CVE-2025-9100",
		Upstream: assessment.UpstreamData{
			Description: originalDesc,
		},
	}

	s := newTestService(ctx, t, store, dir, baseline)
	merged, cs, err := s.Process(ctx, incoming)
	require.NoError(t, err)

	// Change set: Unchanged (computed data did not change relative to baseline).
	assert.Equal(t, assessment.Unchanged, cs.Type)
	assert.False(t, cs.HasChanges())

	// Merged result must carry the computed value.
	assert.Equal(t, originalDesc, merged.Upstream.Description)

	// The file on disk must have been reverted to the computed value.
	got, err := store.Get("CVE-2025-9100")
	require.NoError(t, err)
	assert.Equal(t, originalDesc, got.Upstream.Description,
		"store must be updated: bot's stale value must be reverted")
}

func TestServiceProcess_FirstRunUsesEmptyBaseline(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := assessment.NewStore(&config.AppConfig{AssessmentsDir: dir})
	ctx := t.Context()

	// Record exists on disk but there is no baseline commit yet (first run).
	// The baseline must be empty, so the on-disk manual field is an addition.
	existing := assessment.Record{
		ID: "CVE-2025-1234",
		Upstream: assessment.UpstreamData{
			Description: "A vuln.",
		},
		Manual: assessment.ManualOverride{
			ManualTriage: assessment.Triage{
				Status: assessment.StatusNotRelevant, Justification: "human says no",
			},
		},
	}
	require.NoError(t, store.Save(existing))

	incoming := assessment.Record{
		ID: "CVE-2025-1234",
		Upstream: assessment.UpstreamData{
			Description: "A vuln.",
		},
	}

	// No baseline records => newTestService uses an empty commitSHA (first run).
	s := newTestService(ctx, t, store, dir)
	merged, cs, err := s.Process(ctx, incoming)
	require.NoError(t, err)

	// Preserve field is kept in the merged result.
	assert.Equal(t, assessment.StatusNotRelevant, merged.Manual.ManualTriage.Status)

	// Diffed against the empty baseline, the manual field appears as an addition.
	assert.True(t, cs.HasChanges())
	changeMap := make(map[string]assessment.FieldChange)
	for _, c := range cs.Changes {
		changeMap[c.Field.String()] = c
	}
	assert.Contains(t, changeMap, "manual.manual_triage.status")
	assert.Empty(t, changeMap["manual.manual_triage.status"].OldValue,
		"baseline must be empty on first run, so the on-disk manual value is an addition")
	assert.Equal(t, "not-relevant", changeMap["manual.manual_triage.status"].NewValue)
}

func TestServiceProcess_Unchanged(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := assessment.NewStore(&config.AppConfig{AssessmentsDir: dir})
	ctx := t.Context()

	rec := assessment.Record{
		ID: "CVE-2025-8000",
		Upstream: assessment.UpstreamData{
			Description: "Stable vuln.",
		},
		Screening: assessment.ScreeningResult{
			AutoTriage: assessment.Triage{Status: assessment.StatusRelevant, Justification: "reason"},
		},
		Releases: map[string]assessment.ReleaseDecision{
			"2150.8.0": {
				AutoTriage: assessment.ReleaseTriage{
					Status: assessment.ImpactAffected, Justification: "ships it",
				},
			},
		},
	}
	require.NoError(t, store.Save(rec))

	// Process same data with itself as baseline → unchanged.
	s := newTestService(ctx, t, store, dir, rec)
	_, cs, err := s.Process(ctx, rec)
	require.NoError(t, err)

	assert.Equal(t, assessment.Unchanged, cs.Type)
	assert.False(t, cs.HasChanges())
}
