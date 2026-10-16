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

	vulnerable := assessment.PackageStatus{Reason: assessment.ReleaseReasonVersionVulnerable}
	fixed := assessment.PackageStatus{Reason: assessment.ReleaseReasonVersionFixed}

	tests := []struct {
		name    string
		rec     assessment.Record
		release string
		want    assessment.ReleaseStatus
	}{
		{
			name: "auto only for release",
			rec: assessment.Record{
				Releases: map[string]assessment.ReleaseDecision{
					"2150.8.0": {Auto: assessment.AutoReleaseStatus{Packages: map[string]assessment.PackageStatus{
						"pkg:deb/debian/foo": vulnerable,
					}}},
				},
			},
			release: "2150.8.0",
			want:    assessment.ReleaseStatusAffected,
		},
		{
			name: "manual override flips composite for release",
			rec: assessment.Record{
				Releases: map[string]assessment.ReleaseDecision{
					"2150.8.0": {
						Auto: assessment.AutoReleaseStatus{Packages: map[string]assessment.PackageStatus{
							"pkg:deb/debian/foo": vulnerable,
						}},
						Manual: assessment.ManualReleaseStatus{Packages: map[string]assessment.PackageOverride{
							"pkg:deb/debian/foo": {Status: assessment.ReleaseStatusNotAffected},
						}},
					},
				},
			},
			release: "2150.8.0",
			want:    assessment.ReleaseStatusNotAffected,
		},
		{
			name: "one vulnerable source keeps release affected",
			rec: assessment.Record{
				Releases: map[string]assessment.ReleaseDecision{
					"2150.8.0": {Auto: assessment.AutoReleaseStatus{Packages: map[string]assessment.PackageStatus{
						"pkg:deb/debian/foo": fixed,
						"pkg:deb/debian/bar": vulnerable,
					}}},
				},
			},
			release: "2150.8.0",
			want:    assessment.ReleaseStatusAffected,
		},
		{
			name: "empty decision rolls up to not-affected (package-not-shipped)",
			rec: assessment.Record{
				Releases: map[string]assessment.ReleaseDecision{
					"2150.8.0": {},
				},
			},
			release: "2150.8.0",
			want:    assessment.ReleaseStatusNotAffected,
		},
		{
			name: "release not present",
			rec: assessment.Record{
				Releases: map[string]assessment.ReleaseDecision{
					"2150.8.0": {Auto: assessment.AutoReleaseStatus{Packages: map[string]assessment.PackageStatus{
						"pkg:deb/debian/foo": vulnerable,
					}}},
				},
			},
			release: "1596.0",
			want:    assessment.ReleaseStatusUnknown,
		},
		{
			name:    "nil releases map",
			rec:     assessment.Record{},
			release: "2150.8.0",
			want:    assessment.ReleaseStatusUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, tt.rec.GetReleaseStatus(tt.release))
		})
	}
}

func TestReleaseStatusReason_NeedsEscalation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		reason        assessment.ReleaseStatusReason
		wantStatus    assessment.ReleaseStatus
		wantEscalates bool
	}{
		{assessment.ReleaseReasonPackageNotShipped, assessment.ReleaseStatusNotAffected, false},
		{assessment.ReleaseReasonDeclaredNotAffected, assessment.ReleaseStatusNotAffected, false},
		{assessment.ReleaseReasonVersionFixed, assessment.ReleaseStatusFixed, false},
		{assessment.ReleaseReasonVersionVulnerable, assessment.ReleaseStatusAffected, false},
		{assessment.ReleaseReasonAffectedEscalated, assessment.ReleaseStatusAffected, true},
		{assessment.ReleaseReasonUnknownEscalated, assessment.ReleaseStatusUnknown, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.reason), func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.wantStatus, tt.reason.Status())
			assert.Equal(t, tt.wantEscalates, tt.reason.NeedsEscalation())
		})
	}
}

func TestReleaseDecision_CompositePrecedence(t *testing.T) {
	t.Parallel()

	src := func(r assessment.ReleaseStatusReason) assessment.PackageStatus {
		return assessment.PackageStatus{Reason: r}
	}

	tests := []struct {
		name          string
		packages      map[string]assessment.PackageStatus
		wantReason    assessment.ReleaseStatusReason
		wantStatus    assessment.ReleaseStatus
		wantEscalates bool
	}{
		{
			name: "version-vulnerable dominates unknown-escalated without escalation",
			packages: map[string]assessment.PackageStatus{
				"a": src(assessment.ReleaseReasonVersionVulnerable),
				"b": src(assessment.ReleaseReasonUnknownEscalated),
			},
			wantReason:    assessment.ReleaseReasonVersionVulnerable,
			wantStatus:    assessment.ReleaseStatusAffected,
			wantEscalates: false,
		},
		{
			name: "affected-escalated dominates version-fixed",
			packages: map[string]assessment.PackageStatus{
				"a": src(assessment.ReleaseReasonAffectedEscalated),
				"b": src(assessment.ReleaseReasonVersionFixed),
			},
			wantReason:    assessment.ReleaseReasonAffectedEscalated,
			wantStatus:    assessment.ReleaseStatusAffected,
			wantEscalates: true,
		},
		{
			name: "unknown-escalated dominates version-fixed and escalates",
			packages: map[string]assessment.PackageStatus{
				"a": src(assessment.ReleaseReasonUnknownEscalated),
				"b": src(assessment.ReleaseReasonVersionFixed),
			},
			wantReason:    assessment.ReleaseReasonUnknownEscalated,
			wantStatus:    assessment.ReleaseStatusUnknown,
			wantEscalates: true,
		},
		{
			name: "version-fixed dominates declared-not-affected",
			packages: map[string]assessment.PackageStatus{
				"a": src(assessment.ReleaseReasonVersionFixed),
				"b": src(assessment.ReleaseReasonDeclaredNotAffected),
			},
			wantReason:    assessment.ReleaseReasonVersionFixed,
			wantStatus:    assessment.ReleaseStatusFixed,
			wantEscalates: false,
		},
		{
			name:          "no packages rolls up to package-not-shipped",
			packages:      nil,
			wantReason:    assessment.ReleaseReasonPackageNotShipped,
			wantStatus:    assessment.ReleaseStatusNotAffected,
			wantEscalates: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			d := assessment.ReleaseDecision{Auto: assessment.AutoReleaseStatus{Packages: tt.packages}}
			assert.Equal(t, tt.wantReason, d.CompositeReason())
			assert.Equal(t, tt.wantStatus, d.CompositeStatus())
			assert.Equal(t, tt.wantEscalates, d.NeedsEscalation())
		})
	}
}

func TestReleaseDecision_ManualOverrideRecomputesComposite(t *testing.T) {
	t.Parallel()

	// A single affected package, overridden to not-affected, flips the headline.
	d := assessment.ReleaseDecision{
		Auto: assessment.AutoReleaseStatus{Packages: map[string]assessment.PackageStatus{
			"pkg:deb/debian/foo": {Reason: assessment.ReleaseReasonVersionVulnerable},
		}},
		Manual: assessment.ManualReleaseStatus{Packages: map[string]assessment.PackageOverride{
			"pkg:deb/debian/foo": {
				Status:        assessment.ReleaseStatusNotAffected,
				Justification: "vulnerable path not present",
			},
		}},
	}

	assert.Equal(t, assessment.ReleaseReasonDeclaredNotAffected, d.CompositeReason())
	assert.Equal(t, assessment.ReleaseStatusNotAffected, d.CompositeStatus())
	assert.False(t, d.NeedsEscalation())
}

func TestPackageStatus_MarshalJSON(t *testing.T) {
	t.Parallel()

	data, err := json.Marshal(assessment.PackageStatus{
		Reason:         assessment.ReleaseReasonVersionVulnerable,
		ShippedVersion: "1.0-1",
	})
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))

	assert.Equal(t, "affected", m["status"], "derived status emitted")
	assert.Equal(t, "version-vulnerable", m["reason"])
	assert.Equal(t, "1.0-1", m["shipped_version"])
}

func TestReleaseDecision_MarshalJSON_Composite(t *testing.T) {
	t.Parallel()

	d := assessment.ReleaseDecision{
		Auto: assessment.AutoReleaseStatus{Packages: map[string]assessment.PackageStatus{
			"pkg:deb/debian/foo": {Reason: assessment.ReleaseReasonUnknownEscalated},
		}},
	}

	data, err := json.Marshal(d)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))

	composite, ok := m["composite"].(map[string]any)
	require.True(t, ok, "composite object emitted")
	assert.Equal(t, "unknown", composite["status"])
	assert.Equal(t, "unknown-escalated", composite["reason"])
	assert.Equal(t, true, composite["escalates"])
}

// TestReleaseDecision_UnmarshalJSON_DerivedIgnored verifies the derived composite/status
// keys are ignored on read, so a round-trip restores only the stored reasons.
func TestReleaseDecision_UnmarshalJSON_DerivedIgnored(t *testing.T) {
	t.Parallel()

	raw := `{"composite":{"status":"fixed","reason":"version-fixed"},` +
		`"auto":{"packages":{"pkg:deb/debian/foo":{"status":"fixed","reason":"version-vulnerable"}}}}`

	var d assessment.ReleaseDecision
	require.NoError(t, json.Unmarshal([]byte(raw), &d))

	got := d.Auto.Packages["pkg:deb/debian/foo"]
	assert.Equal(t, assessment.ReleaseReasonVersionVulnerable, got.Reason)
	// Composite derives from the stored reason, not the JSON composite field.
	assert.Equal(t, assessment.ReleaseReasonVersionVulnerable, d.CompositeReason())
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

func TestPackageOverride_IsEmpty(t *testing.T) {
	t.Parallel()

	assert.True(t, assessment.PackageOverride{}.IsEmpty())
	assert.True(t, assessment.PackageOverride{Justification: "reason but no status"}.IsEmpty())
	assert.False(t, assessment.PackageOverride{Status: assessment.ReleaseStatusFixed}.IsEmpty())
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
		"Auto":   "overwrite",
		"Manual": "preserve",
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
