package screening_test

import (
	"testing"

	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/gardenlinux/glvd2/internal/screening"
	"github.com/stretchr/testify/assert"
)

func TestScreen_Rules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		in          screening.Input
		wantReason  assessment.TriageReason
		wantStatus  assessment.TriageStatus
		wantMatched []string
	}{
		{
			name: "REJECTED beats everything",
			in: screening.Input{
				Rejected:        true,
				CuratedMatches:  []string{"pkg:deb/gardenlinux/foo"},
				VendoredMatches: []string{"pkg:deb/gardenlinux/bar"},
				DebianAssigned:  true,
				DebianShipped:   []string{"pkg:deb/debian/baz"},
				DebianNotForUs:  true,
			},
			wantReason: assessment.TriageReasonRejectedUpstream,
			wantStatus: assessment.StatusNotRelevant,
		},
		{
			name: "curated GL map beats NFU, gate and vendored",
			in: screening.Input{
				CuratedMatches:  []string{"pkg:deb/gardenlinux/foo"},
				VendoredMatches: []string{"pkg:deb/gardenlinux/bar"},
				DebianAssigned:  true,
				DebianShipped:   []string{"pkg:deb/debian/bar"},
				DebianNotForUs:  true,
			},
			wantReason:  assessment.TriageReasonAffectsGardenLinuxPackage,
			wantStatus:  assessment.StatusRelevant,
			wantMatched: []string{"pkg:deb/gardenlinux/foo"},
		},
		{
			name: "vendored beats gate and NFU when curated silent",
			in: screening.Input{
				VendoredMatches: []string{"pkg:deb/gardenlinux/bar"},
				DebianAssigned:  true,
				DebianShipped:   nil, // gate would mark not-shipped, but vendored wins first
				DebianAllPURLs:  []string{"pkg:deb/debian/baz"},
			},
			wantReason:  assessment.TriageReasonAffectsVendoredDependency,
			wantStatus:  assessment.StatusRelevant,
			wantMatched: []string{"pkg:deb/gardenlinux/bar"},
		},
		{
			name: "Debian package shipped in inventory",
			in: screening.Input{
				DebianAssigned: true,
				DebianShipped:  []string{"pkg:deb/debian/baz"},
				DebianAllPURLs: []string{"pkg:deb/debian/baz"},
			},
			wantReason:  assessment.TriageReasonAffectsDebianPackage,
			wantStatus:  assessment.StatusRelevant,
			wantMatched: []string{"pkg:deb/debian/baz"},
		},
		{
			name: "Debian package not shipped still records resolved PURL",
			in: screening.Input{
				DebianAssigned: true,
				DebianShipped:  nil,
				DebianAllPURLs: []string{"pkg:deb/debian/baz"},
			},
			wantReason:  assessment.TriageReasonDebianPackageNotShipped,
			wantStatus:  assessment.StatusNotRelevant,
			wantMatched: []string{"pkg:deb/debian/baz"},
		},
		{
			name: "Debian package not shipped with no resolved PURLs",
			in: screening.Input{
				DebianAssigned: true,
				DebianShipped:  nil,
				DebianAllPURLs: nil,
			},
			wantReason: assessment.TriageReasonDebianPackageNotShipped,
			wantStatus: assessment.StatusNotRelevant,
		},
		{
			name: "Debian assigned beats NOT-FOR-US",
			in: screening.Input{
				DebianAssigned: true,
				DebianShipped:  []string{"pkg:deb/debian/baz"},
				DebianAllPURLs: []string{"pkg:deb/debian/baz"},
				DebianNotForUs: true,
			},
			wantReason:  assessment.TriageReasonAffectsDebianPackage,
			wantStatus:  assessment.StatusRelevant,
			wantMatched: []string{"pkg:deb/debian/baz"},
		},
		{
			name: "NOT-FOR-US with no gl-specific mapping",
			in: screening.Input{
				DebianNotForUs: true,
			},
			wantReason: assessment.TriageReasonDebianNotForUs,
			wantStatus: assessment.StatusNotRelevant,
		},
		{
			name:       "nothing resolves yet",
			in:         screening.Input{},
			wantReason: assessment.TriageReasonAwaitingDebian,
			wantStatus: assessment.StatusUndecided,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := screening.Screen(tt.in)

			assert.Equal(t, tt.wantReason, got.AutoTriage.Reason)
			assert.Equal(t, tt.wantStatus, got.AutoTriage.Status())
			assert.Equal(t, tt.wantMatched, got.Matched)
		})
	}
}
