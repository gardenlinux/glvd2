package assessment //nolint:testpackage // white-box tests require access to unexported types

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectExternalOverwriteEdits(t *testing.T) {
	t.Parallel()

	schema := newMergeSpec[Record]()

	tests := []struct {
		name       string
		baseline   Record
		existing   Record
		wantFields []string // dot-joined field paths expected in result
		wantEmpty  bool
	}{
		{
			name: "overwrite field edited externally - detected",
			baseline: Record{
				ID: "CVE-2025-9001",
				Screening: ScreeningResult{
					AutoTriage: Triage{Status: StatusRelevant, Justification: "original"},
				},
			},
			existing: Record{
				ID: "CVE-2025-9001",
				Screening: ScreeningResult{
					AutoTriage: Triage{Status: StatusNotRelevant, Justification: "bot changed this"},
				},
			},
			wantFields: []string{"screening.auto_triage.status", "screening.auto_triage.justification"},
		},
		{
			name: "preserve field edited externally - ignored",
			baseline: Record{
				ID: "CVE-2025-9002",
				Manual: ManualOverride{
					ManualTriage: Triage{Status: StatusRelevant},
				},
			},
			existing: Record{
				ID: "CVE-2025-9002",
				Manual: ManualOverride{
					ManualTriage: Triage{Status: StatusNotRelevant},
				},
			},
			wantEmpty: true,
		},
		{
			name: "legitimate program change (baseline == existing) - no false positive",
			baseline: Record{
				ID: "CVE-2025-9003",
				Screening: ScreeningResult{
					AutoTriage: Triage{Status: StatusRelevant},
				},
			},
			existing: Record{
				ID: "CVE-2025-9003",
				Screening: ScreeningResult{
					AutoTriage: Triage{Status: StatusRelevant}, // same as baseline
				},
			},
			wantEmpty: true,
		},
		{
			name: "map overwrite subfield edited externally - detected",
			baseline: Record{
				ID: "CVE-2025-9004",
				Releases: map[string]ReleaseDecision{
					"2150.8.0": {
						AutoTriage: ReleaseTriage{Status: ImpactAffected, Justification: "ships it"},
					},
				},
			},
			existing: Record{
				ID: "CVE-2025-9004",
				Releases: map[string]ReleaseDecision{
					"2150.8.0": {
						AutoTriage: ReleaseTriage{Status: ImpactFixed, Justification: "bot patched it"},
					},
				},
			},
			wantFields: []string{"releases.2150.8.0.auto_triage.status", "releases.2150.8.0.auto_triage.justification"},
		},
		{
			name: "map preserve subfield edited externally - ignored",
			baseline: Record{
				ID: "CVE-2025-9005",
				Releases: map[string]ReleaseDecision{
					"2150.8.0": {
						ManualTriage: ReleaseTriage{Status: ImpactAffected},
					},
				},
			},
			existing: Record{
				ID: "CVE-2025-9005",
				Releases: map[string]ReleaseDecision{
					"2150.8.0": {
						ManualTriage: ReleaseTriage{Status: ImpactNotAffected},
					},
				},
			},
			wantEmpty: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			edits := detectExternalOverwriteEdits(schema, tc.baseline, tc.existing)

			if tc.wantEmpty {
				assert.Empty(t, edits)
				return
			}

			got := make(map[string]struct{}, len(edits))
			for _, e := range edits {
				got[e.Field.String()] = struct{}{}
			}
			for _, wf := range tc.wantFields {
				assert.Contains(t, got, wf, "expected field %q in external overwrite edits", wf)
			}
		})
	}
}

// diffItems is a type-safe generic helper to test [diffStructs] with synthetic structs.
func diffItems[T any](old, updated T) []FieldChange {
	cache := newMergeSpec[T]()
	return diffStructs(cache, old, updated)
}

func TestDiffRecords_Created(t *testing.T) {
	t.Parallel()

	schema := newMergeSpec[Record]()

	merged := Record{
		ID: "CVE-2025-1001",
		Upstream: UpstreamData{
			Description: "New vuln.",
		},
		Screening: ScreeningResult{
			AutoTriage:    Triage{Status: StatusRelevant, Justification: "reason"},
			PriorityScore: 7.5,
		},
	}

	// Empty baseline means this is a new record.
	cs := diffRecords(schema, Record{}, merged)

	assert.Equal(t, Created, cs.Type)
	assert.Equal(t, "CVE-2025-1001", cs.CVEID)
	assert.True(t, cs.HasChanges())

	fieldNames := make([]string, 0, len(cs.Changes))
	for _, c := range cs.Changes {
		fieldNames = append(fieldNames, c.Field.String())
	}
	assert.Contains(t, fieldNames, "upstream.description")
	assert.Contains(t, fieldNames, "screening.auto_triage.status")
	assert.Contains(t, fieldNames, "screening.auto_triage.justification")
	assert.Contains(t, fieldNames, "screening.priority_score")
}

func TestDiffRecords_Updated_Description(t *testing.T) {
	t.Parallel()

	schema := newMergeSpec[Record]()

	baseline := Record{
		ID: "CVE-2025-2001",
		Upstream: UpstreamData{
			Description: "Old desc.",
		},
		Screening: ScreeningResult{
			AutoTriage: Triage{Status: StatusRelevant, Justification: "reason"},
		},
	}

	merged := Record{
		ID: "CVE-2025-2001",
		Upstream: UpstreamData{
			Description: "New desc.",
		},
		Screening: ScreeningResult{
			AutoTriage: Triage{Status: StatusRelevant, Justification: "reason"},
		},
	}

	cs := diffRecords(schema, baseline, merged)

	assert.Equal(t, Updated, cs.Type)
	require.Len(t, cs.Changes, 1)
	assert.Equal(t, FieldPath{"upstream", "description"}, cs.Changes[0].Field)
	assert.Equal(t, "Old desc.", cs.Changes[0].OldValue)
	assert.Equal(t, "New desc.", cs.Changes[0].NewValue)
}

func TestDiffRecords_Updated_AutoTriageStatus(t *testing.T) {
	t.Parallel()

	schema := newMergeSpec[Record]()

	baseline := Record{
		ID: "CVE-2025-3001",
		Screening: ScreeningResult{
			AutoTriage: Triage{Status: StatusRelevant, Justification: "old"},
		},
	}

	merged := Record{
		ID: "CVE-2025-3001",
		Screening: ScreeningResult{
			AutoTriage: Triage{Status: StatusCritical, Justification: "CVSS bumped"},
		},
	}

	cs := diffRecords(schema, baseline, merged)

	assert.Equal(t, Updated, cs.Type)

	changeMap := make(map[string]FieldChange)
	for _, c := range cs.Changes {
		changeMap[c.Field.String()] = c
	}

	assert.Equal(t, "relevant", changeMap["screening.auto_triage.status"].OldValue)
	assert.Equal(t, "critical", changeMap["screening.auto_triage.status"].NewValue)
	assert.Equal(t, "old", changeMap["screening.auto_triage.justification"].OldValue)
	assert.Equal(t, "CVSS bumped", changeMap["screening.auto_triage.justification"].NewValue)
}

func TestDiffRecords_Updated_PriorityScore(t *testing.T) {
	t.Parallel()

	schema := newMergeSpec[Record]()

	baseline := Record{
		ID: "CVE-2025-3501",
		Screening: ScreeningResult{
			PriorityScore: 5.0,
		},
	}

	merged := Record{
		ID: "CVE-2025-3501",
		Screening: ScreeningResult{
			PriorityScore: 9.8,
		},
	}

	cs := diffRecords(schema, baseline, merged)

	assert.Equal(t, Updated, cs.Type)
	require.Len(t, cs.Changes, 1)
	assert.Equal(t, FieldPath{"screening", "priority_score"}, cs.Changes[0].Field)
	assert.Equal(t, "5", cs.Changes[0].OldValue)
	assert.Equal(t, "9.8", cs.Changes[0].NewValue)
}

func TestDiffRecords_Updated_ReleaseAutoStatus(t *testing.T) {
	t.Parallel()

	schema := newMergeSpec[Record]()

	baseline := Record{
		ID: "CVE-2025-4001",
		Releases: map[string]ReleaseDecision{
			"2150.8.0": {
				AutoTriage: ReleaseTriage{
					Status: ImpactAffected, Justification: "ships 1.0",
				},
			},
		},
	}

	merged := Record{
		ID: "CVE-2025-4001",
		Releases: map[string]ReleaseDecision{
			"2150.8.0": {
				AutoTriage: ReleaseTriage{
					Status: ImpactFixed, Justification: "ships 1.1",
				},
			},
		},
	}

	cs := diffRecords(schema, baseline, merged)

	assert.Equal(t, Updated, cs.Type)

	changeMap := make(map[string]FieldChange)
	for _, c := range cs.Changes {
		changeMap[c.Field.String()] = c
	}

	assert.Equal(t, "affected", changeMap["releases.2150.8.0.auto_triage.status"].OldValue)
	assert.Equal(t, "fixed", changeMap["releases.2150.8.0.auto_triage.status"].NewValue)
}

func TestDiffRecords_Unchanged(t *testing.T) {
	t.Parallel()

	schema := newMergeSpec[Record]()

	rec := Record{
		ID: "CVE-2025-5001",
		Upstream: UpstreamData{
			Description: "Stable.",
		},
		Screening: ScreeningResult{
			AutoTriage: Triage{Status: StatusNotRelevant, Justification: "reason"},
		},
	}

	cs := diffRecords(schema, rec, rec)

	assert.Equal(t, Unchanged, cs.Type)
	assert.False(t, cs.HasChanges())
	assert.Empty(t, cs.Changes)
}

func TestDiffRecords_BotEditDetected(t *testing.T) {
	t.Parallel()

	schema := newMergeSpec[Record]()

	// Baseline is what the program wrote last time.
	baseline := Record{
		ID: "CVE-2025-6001",
		Screening: ScreeningResult{
			AutoTriage: Triage{Status: StatusRelevant, Justification: "reason"},
		},
		Releases: map[string]ReleaseDecision{
			"2150.8.0": {
				AutoTriage: ReleaseTriage{
					Status: ImpactAffected, Justification: "ships it",
				},
			},
		},
	}

	// Merged result includes bot's manual edits (preserved from disk) + unchanged auto fields.
	merged := Record{
		ID: "CVE-2025-6001",
		Screening: ScreeningResult{
			AutoTriage: Triage{Status: StatusRelevant, Justification: "reason"},
		},
		Manual: ManualOverride{
			ManualTriage: Triage{
				Status: StatusNotRelevant, Justification: "human decided",
			},
		},
		Releases: map[string]ReleaseDecision{
			"2150.8.0": {
				AutoTriage: ReleaseTriage{
					Status: ImpactAffected, Justification: "ships it",
				},
				ManualTriage: ReleaseTriage{
					Status: ImpactNotAffected, Justification: "disabled",
				},
			},
		},
	}

	cs := diffRecords(schema, baseline, merged)

	assert.Equal(t, Updated, cs.Type)
	assert.True(t, cs.HasChanges())

	changeMap := make(map[string]FieldChange)
	for _, c := range cs.Changes {
		changeMap[c.Field.String()] = c
	}

	assert.Contains(t, changeMap, "manual.manual_triage.status")
	assert.Empty(t, changeMap["manual.manual_triage.status"].OldValue)
	assert.Equal(t, "not-relevant", changeMap["manual.manual_triage.status"].NewValue)

	assert.Contains(t, changeMap, "releases.2150.8.0.manual_triage.status")
	assert.Empty(t, changeMap["releases.2150.8.0.manual_triage.status"].OldValue)
	assert.Equal(t, "not-affected", changeMap["releases.2150.8.0.manual_triage.status"].NewValue)
}

func TestDiffRecords_NewReleaseAdded(t *testing.T) {
	t.Parallel()

	schema := newMergeSpec[Record]()

	baseline := Record{
		ID: "CVE-2025-7001",
		Screening: ScreeningResult{
			AutoTriage: Triage{Status: StatusRelevant},
		},
		Releases: map[string]ReleaseDecision{
			"2150.8.0": {AutoTriage: ReleaseTriage{Status: ImpactAffected}},
		},
	}

	merged := Record{
		ID: "CVE-2025-7001",
		Screening: ScreeningResult{
			AutoTriage: Triage{Status: StatusRelevant},
		},
		Releases: map[string]ReleaseDecision{
			"2150.8.0": {AutoTriage: ReleaseTriage{Status: ImpactAffected}},
			"1596.0": {
				AutoTriage: ReleaseTriage{
					Status: ImpactFixed, Justification: "patched",
				},
			},
		},
	}

	cs := diffRecords(schema, baseline, merged)

	assert.Equal(t, Updated, cs.Type)

	changeMap := make(map[string]FieldChange)
	for _, c := range cs.Changes {
		changeMap[c.Field.String()] = c
	}

	assert.Contains(t, changeMap, "releases.1596.0.auto_triage.status")
	assert.Empty(t, changeMap["releases.1596.0.auto_triage.status"].OldValue)
	assert.Equal(t, "fixed", changeMap["releases.1596.0.auto_triage.status"].NewValue)
}

func TestDiffRecords_Updated_CVSSScore(t *testing.T) {
	t.Parallel()

	schema := newMergeSpec[Record]()

	baseline := Record{
		ID: "CVE-2025-8001",
		Upstream: UpstreamData{
			CVSSv3: &CVSSScore{Score: 7.5, Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
		},
	}

	merged := Record{
		ID: "CVE-2025-8001",
		Upstream: UpstreamData{
			CVSSv3: &CVSSScore{Score: 9.8, Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		},
	}

	cs := diffRecords(schema, baseline, merged)

	assert.Equal(t, Updated, cs.Type)

	changeMap := make(map[string]FieldChange)
	for _, c := range cs.Changes {
		changeMap[c.Field.String()] = c
	}

	assert.Equal(t, "7.5", changeMap["upstream.cvss_v3.score"].OldValue)
	assert.Equal(t, "9.8", changeMap["upstream.cvss_v3.score"].NewValue)
	assert.Contains(t, changeMap, "upstream.cvss_v3.vector")
}

// --- Generic diff tests (using test structs) ---

func TestDiff_NoChanges(t *testing.T) {
	t.Parallel()

	item := testItem{ID: "x", Name: "same", Score: 1.0, UserNote: "note"}

	changes := diffItems(item, item)
	assert.Empty(t, changes)
}

func TestDiff_OverwriteFieldChanged(t *testing.T) {
	t.Parallel()

	old := testItem{ID: "x", Name: "old", Score: 1.0}
	updated := testItem{ID: "x", Name: "new", Score: 9.8}

	changes := diffItems(old, updated)

	changeMap := make(map[string]FieldChange)
	for _, c := range changes {
		changeMap[c.Field.String()] = c
	}

	assert.Equal(t, "old", changeMap["name"].OldValue)
	assert.Equal(t, "new", changeMap["name"].NewValue)
	assert.Equal(t, "1", changeMap["score"].OldValue)
	assert.Equal(t, "9.8", changeMap["score"].NewValue)
}

func TestDiff_PreserveFieldIncluded(t *testing.T) {
	t.Parallel()

	old := testItem{ID: "x", Name: "same", UserNote: "old note"}
	updated := testItem{ID: "x", Name: "same", UserNote: "new note"}

	changes := diffItems(old, updated)

	// Preserve fields ARE now included in diff (needed to detect bot edits).
	changeMap := make(map[string]FieldChange)
	for _, c := range changes {
		changeMap[c.Field.String()] = c
	}
	assert.Equal(t, "old note", changeMap["user_note"].OldValue)
	assert.Equal(t, "new note", changeMap["user_note"].NewValue)
}

func TestDiff_KeyFieldExcluded(t *testing.T) {
	t.Parallel()

	old := testItem{ID: "x", Name: "same"}
	updated := testItem{ID: "y", Name: "same"}

	changes := diffItems(old, updated)

	// Key field is NOT diffed (it's identity, should never change).
	assert.Empty(t, changes)
}

func TestDiff_NestedStructDiff(t *testing.T) {
	t.Parallel()

	old := testNested{
		ID:   "n-1",
		Data: testInner{Value: "old", Count: 1},
		Keep: testInner{Value: "a", Count: 1},
	}
	updated := testNested{
		ID:   "n-1",
		Data: testInner{Value: "new", Count: 42},
		Keep: testInner{Value: "b", Count: 2},
	}

	changes := diffItems(old, updated)

	changeMap := make(map[string]FieldChange)
	for _, c := range changes {
		changeMap[c.Field.String()] = c
	}

	// Overwrite struct fields.
	assert.Equal(t, "old", changeMap["data.value"].OldValue)
	assert.Equal(t, "new", changeMap["data.value"].NewValue)
	assert.Equal(t, "1", changeMap["data.count"].OldValue)
	assert.Equal(t, "42", changeMap["data.count"].NewValue)
	// Preserve struct fields - now included in diff.
	assert.Equal(t, "a", changeMap["keep.value"].OldValue)
	assert.Equal(t, "b", changeMap["keep.value"].NewValue)
	assert.Equal(t, "1", changeMap["keep.count"].OldValue)
	assert.Equal(t, "2", changeMap["keep.count"].NewValue)
}

func TestDiff_MapFieldDiff(t *testing.T) {
	t.Parallel()

	old := testWithMap{
		ID:    "m-1",
		Title: "same",
		Items: map[string]testMapValue{
			"a": {Status: "active", Comment: "note"},
		},
	}
	updated := testWithMap{
		ID:    "m-1",
		Title: "same",
		Items: map[string]testMapValue{
			"a": {Status: "closed", Comment: "changed note"},
		},
	}

	changes := diffItems(old, updated)

	changeMap := make(map[string]FieldChange)
	for _, c := range changes {
		changeMap[c.Field.String()] = c
	}

	// Overwrite field in map value: diffed.
	assert.Equal(t, "active", changeMap["items.a.status"].OldValue)
	assert.Equal(t, "closed", changeMap["items.a.status"].NewValue)
	// Preserve field in map value: ALSO diffed now.
	assert.Equal(t, "note", changeMap["items.a.comment"].OldValue)
	assert.Equal(t, "changed note", changeMap["items.a.comment"].NewValue)
}

func TestDiff_MapNewKey(t *testing.T) {
	t.Parallel()

	old := testWithMap{
		ID:    "m-1",
		Title: "same",
		Items: map[string]testMapValue{},
	}
	updated := testWithMap{
		ID:    "m-1",
		Title: "same",
		Items: map[string]testMapValue{
			"new-key": {Status: "active"},
		},
	}

	changes := diffItems(old, updated)

	changeMap := make(map[string]FieldChange)
	for _, c := range changes {
		changeMap[c.Field.String()] = c
	}

	assert.Empty(t, changeMap["items.new-key.status"].OldValue)
	assert.Equal(t, "active", changeMap["items.new-key.status"].NewValue)
}

func TestDiffValue_TimeFields(t *testing.T) {
	t.Parallel()

	t1 := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2024, 6, 6, 12, 30, 0, 0, time.UTC)
	// Same instant as t1 but expressed in a non-UTC zone - MarshalJSON normalizes to UTC,
	// so this must not be reported as a change.
	t1InCET := time.Date(2020, 1, 1, 1, 0, 0, 0, time.FixedZone("CET", 3600))

	tests := []struct {
		name         string
		old          Record
		updated      Record
		wantField    string
		wantChange   bool
		wantOldValue string
		wantNewValue string
	}{
		{
			name:         "published_at changed",
			old:          Record{ID: "CVE-2025-1", Upstream: UpstreamData{PublishedAt: t1}},
			updated:      Record{ID: "CVE-2025-1", Upstream: UpstreamData{PublishedAt: t2}},
			wantField:    "upstream.published_at",
			wantChange:   true,
			wantOldValue: `"2020-01-01T00:00:00Z"`,
			wantNewValue: `"2024-06-06T12:30:00Z"`,
		},
		{
			name:         "first_seen_at changed",
			old:          Record{ID: "CVE-2025-1", Meta: Metadata{FirstSeenAt: t1}},
			updated:      Record{ID: "CVE-2025-1", Meta: Metadata{FirstSeenAt: t2}},
			wantField:    "meta.first_seen_at",
			wantChange:   true,
			wantOldValue: `"2020-01-01T00:00:00Z"`,
			wantNewValue: `"2024-06-06T12:30:00Z"`,
		},
		{
			name:       "published_at unchanged",
			old:        Record{ID: "CVE-2025-1", Upstream: UpstreamData{PublishedAt: t1}},
			updated:    Record{ID: "CVE-2025-1", Upstream: UpstreamData{PublishedAt: t1}},
			wantChange: false,
		},
		{
			name:         "same time in different timezone",
			old:          Record{ID: "CVE-2025-1", Upstream: UpstreamData{PublishedAt: t1}},
			updated:      Record{ID: "CVE-2025-1", Upstream: UpstreamData{PublishedAt: t1InCET}},
			wantField:    "upstream.published_at",
			wantChange:   true,
			wantOldValue: `"2020-01-01T00:00:00Z"`,
			wantNewValue: `"2020-01-01T01:00:00+01:00"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			changes := diffItems(tc.old, tc.updated)

			if !tc.wantChange {
				assert.Empty(t, changes)
				return
			}

			changeMap := make(map[string]FieldChange)
			for _, c := range changes {
				changeMap[c.Field.String()] = c
			}

			require.Contains(t, changeMap, tc.wantField)
			fc := changeMap[tc.wantField]
			assert.Equal(t, tc.wantOldValue, fc.OldValue)
			assert.Equal(t, tc.wantNewValue, fc.NewValue)
		})
	}
}
