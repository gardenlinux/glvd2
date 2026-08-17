package assessment_test

import (
	"reflect"
	"testing"

	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/stretchr/testify/assert"
)

func TestRecord_GetGlobalStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		rec  assessment.Record
		want assessment.TriageStatus
	}{
		{
			name: "auto only",
			rec: assessment.Record{
				Screening: assessment.ScreeningResult{
					AutoTriage: assessment.Triage{Status: assessment.StatusRelevant},
				},
			},
			want: assessment.StatusRelevant,
		},
		{
			name: "manual overrides auto",
			rec: assessment.Record{
				Screening: assessment.ScreeningResult{
					AutoTriage: assessment.Triage{Status: assessment.StatusRelevant},
				},
				Manual: assessment.ManualOverride{
					ManualTriage: assessment.Triage{Status: assessment.StatusNotRelevant},
				},
			},
			want: assessment.StatusNotRelevant,
		},
		{
			name: "manual only",
			rec: assessment.Record{
				Manual: assessment.ManualOverride{
					ManualTriage: assessment.Triage{Status: assessment.StatusCritical},
				},
			},
			want: assessment.StatusCritical,
		},
		{
			name: "neither set returns undecided",
			rec:  assessment.Record{},
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

func TestTriage_IsEmpty(t *testing.T) {
	t.Parallel()

	assert.True(t, assessment.Triage{}.IsEmpty())
	assert.True(t, assessment.Triage{Justification: "has reason but no status"}.IsEmpty())
	assert.False(t, assessment.Triage{Status: assessment.StatusRelevant}.IsEmpty())
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
