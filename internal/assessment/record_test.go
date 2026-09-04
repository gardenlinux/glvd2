package assessment_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecord_GetGlobalStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		rec  assessment.Record
		want assessment.TriageStatus
	}{
		{
			name: "auto only - relevant reason",
			rec: assessment.Record{
				Screening: assessment.ScreeningResult{
					AutoTriage: assessment.AutoTriage{Reason: assessment.TriageReasonAffectsDebianPackage},
				},
			},
			want: assessment.StatusRelevant,
		},
		{
			name: "manual overrides auto",
			rec: assessment.Record{
				Screening: assessment.ScreeningResult{
					AutoTriage: assessment.AutoTriage{Reason: assessment.TriageReasonAffectsDebianPackage},
				},
				Manual: assessment.ManualOverride{
					ManualTriage: assessment.ManualTriage{Status: assessment.StatusNotRelevant},
				},
			},
			want: assessment.StatusNotRelevant,
		},
		{
			name: "manual only",
			rec: assessment.Record{
				Manual: assessment.ManualOverride{
					ManualTriage: assessment.ManualTriage{Status: assessment.StatusRelevant},
				},
			},
			want: assessment.StatusRelevant,
		},
		{
			name: "neither set returns undecided",
			rec:  assessment.Record{},
			want: assessment.StatusUndecided,
		},
		{
			name: "auto not-relevant reason",
			rec: assessment.Record{
				Screening: assessment.ScreeningResult{
					AutoTriage: assessment.AutoTriage{Reason: assessment.TriageReasonRejectedUpstream},
				},
			},
			want: assessment.StatusNotRelevant,
		},
		{
			name: "auto awaiting-debian derives undecided",
			rec: assessment.Record{
				Screening: assessment.ScreeningResult{
					AutoTriage: assessment.AutoTriage{Reason: assessment.TriageReasonAwaitingDebian},
				},
			},
			want: assessment.StatusUndecided,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, tt.rec.GetGlobalStatus())
		})
	}
}

func TestRecord_GetReleaseStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		rec     assessment.Record
		release string
		want    assessment.ImpactStatus
	}{
		{
			name: "auto only for release",
			rec: assessment.Record{
				Releases: map[string]assessment.ReleaseDecision{
					"2150.8.0": {AutoTriage: assessment.ReleaseTriage{Status: assessment.ImpactAffected}},
				},
			},
			release: "2150.8.0",
			want:    assessment.ImpactAffected,
		},
		{
			name: "manual overrides auto for release",
			rec: assessment.Record{
				Releases: map[string]assessment.ReleaseDecision{
					"2150.8.0": {
						AutoTriage:   assessment.ReleaseTriage{Status: assessment.ImpactAffected},
						ManualTriage: assessment.ReleaseTriage{Status: assessment.ImpactNotAffected},
					},
				},
			},
			release: "2150.8.0",
			want:    assessment.ImpactNotAffected,
		},
		{
			name: "release not present",
			rec: assessment.Record{
				Releases: map[string]assessment.ReleaseDecision{
					"2150.8.0": {AutoTriage: assessment.ReleaseTriage{Status: assessment.ImpactAffected}},
				},
			},
			release: "1596.0",
			want:    assessment.ImpactUnknown,
		},
		{
			name:    "nil releases map",
			rec:     assessment.Record{},
			release: "2150.8.0",
			want:    assessment.ImpactUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, tt.rec.GetReleaseStatus(tt.release))
		})
	}
}

func TestAutoTriage_Status(t *testing.T) {
	t.Parallel()

	tests := []struct {
		reason assessment.TriageReason
		want   assessment.TriageStatus
	}{
		{assessment.TriageReasonAffectsDebianPackage, assessment.StatusRelevant},
		{assessment.TriageReasonAffectsGardenLinuxPackage, assessment.StatusRelevant},
		{assessment.TriageReasonRejectedUpstream, assessment.StatusNotRelevant},
		{assessment.TriageReasonDebianNotForUs, assessment.StatusNotRelevant},
		{assessment.TriageReasonDebianPackageNotShipped, assessment.StatusNotRelevant},
		{assessment.TriageReasonAwaitingDebian, assessment.StatusUndecided},
		{"", assessment.StatusUndecided},
	}

	for _, tt := range tests {
		t.Run(string(tt.reason), func(t *testing.T) {
			t.Parallel()

			a := assessment.AutoTriage{Reason: tt.reason}
			assert.Equal(t, tt.want, a.Status())
		})
	}
}

func TestAutoTriage_IsEmpty(t *testing.T) {
	t.Parallel()

	assert.True(t, assessment.AutoTriage{}.IsEmpty())
	assert.False(t, assessment.AutoTriage{Reason: assessment.TriageReasonAffectsDebianPackage}.IsEmpty())
}

func TestAutoTriage_MarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		at            assessment.AutoTriage
		wantStatus    string // empty means key must be absent
		wantReason    string
		wantStatusKey bool
	}{
		{
			name:          "relevant reason emits status",
			at:            assessment.AutoTriage{Reason: assessment.TriageReasonAffectsDebianPackage},
			wantStatus:    "relevant",
			wantReason:    "affects-debian-package",
			wantStatusKey: true,
		},
		{
			name:          "not-relevant reason emits status",
			at:            assessment.AutoTriage{Reason: assessment.TriageReasonRejectedUpstream},
			wantStatus:    "not-relevant",
			wantReason:    "rejected-upstream",
			wantStatusKey: true,
		},
		{
			name:          "undecided reason omits status key",
			at:            assessment.AutoTriage{Reason: assessment.TriageReasonAwaitingDebian},
			wantReason:    "awaiting-debian",
			wantStatusKey: false,
		},
		{
			name:          "empty reason omits status key",
			at:            assessment.AutoTriage{},
			wantStatusKey: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			data, err := json.Marshal(tt.at)
			require.NoError(t, err)

			var m map[string]any
			require.NoError(t, json.Unmarshal(data, &m))

			if tt.wantStatusKey {
				assert.Equal(t, tt.wantStatus, m["status"])
			} else {
				assert.NotContains(t, m, "status")
			}

			if tt.wantReason != "" {
				assert.Equal(t, tt.wantReason, m["reason"])
			}
		})
	}
}

// TestAutoTriage_UnmarshalJSON_StatusIgnored verifies that on read the status key is ignored.
func TestAutoTriage_UnmarshalJSON_StatusIgnored(t *testing.T) {
	t.Parallel()

	// JSON with a status that disagrees with what the reason would derive to.
	raw := `{"status":"not-relevant","reason":"affects-debian-package"}`

	var at assessment.AutoTriage
	require.NoError(t, json.Unmarshal([]byte(raw), &at))

	assert.Equal(t, assessment.TriageReasonAffectsDebianPackage, at.Reason)
	// Status() is derived from Reason, not from the JSON status field.
	assert.Equal(t, assessment.StatusRelevant, at.Status())
}

func TestManualTriage_IsEmpty(t *testing.T) {
	t.Parallel()

	assert.True(t, assessment.ManualTriage{}.IsEmpty())
	assert.True(t, assessment.ManualTriage{Justification: "has text but no status"}.IsEmpty())
	assert.False(t, assessment.ManualTriage{Status: assessment.StatusRelevant}.IsEmpty())
}

func TestReleaseTriage_IsEmpty(t *testing.T) {
	t.Parallel()

	assert.True(t, assessment.ReleaseTriage{}.IsEmpty())
	assert.True(t, assessment.ReleaseTriage{Justification: "has reason but no status"}.IsEmpty())
	assert.False(t, assessment.ReleaseTriage{Status: assessment.ImpactFixed}.IsEmpty())
}

func TestRecord_HasMergeTags(t *testing.T) {
	t.Parallel()

	rt := reflect.TypeFor[assessment.Record]()

	expectedTags := map[string]string{
		"ID":        "key",
		"Upstream":  "overwrite",
		"Screening": "overwrite",
		"Manual":    "preserve",
		"Meta":      "preserve",
		"Releases":  "map,preserve",
	}

	for fieldName, expectedTag := range expectedTags {
		field, ok := rt.FieldByName(fieldName)
		if !ok {
			t.Errorf("field %s not found on Assessment", fieldName)
			continue
		}
		got := field.Tag.Get("merge")
		assert.Equal(t, expectedTag, got, "field %s merge tag", fieldName)
	}
}

func TestReleaseDecision_HasMergeTags(t *testing.T) {
	t.Parallel()

	rt := reflect.TypeFor[assessment.ReleaseDecision]()

	expectedTags := map[string]string{
		"AutoTriage":     "overwrite",
		"PackageVersion": "overwrite",
		"FixAvailable":   "overwrite",
		"DebianStatus":   "overwrite",
		"ManualTriage":   "preserve",
	}

	for fieldName, expectedTag := range expectedTags {
		field, ok := rt.FieldByName(fieldName)
		if !ok {
			t.Errorf("field %s not found on ReleaseDecision", fieldName)
			continue
		}
		got := field.Tag.Get("merge")
		assert.Equal(t, expectedTag, got, "field %s merge tag", fieldName)
	}
}
