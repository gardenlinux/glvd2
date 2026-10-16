package releasestatus_test

import (
	"testing"

	"github.com/gardenlinux/glvd2/internal/affectedness"
	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/gardenlinux/glvd2/internal/releasestatus"
	lib "github.com/git-pkgs/vers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	purl  = "pkg:deb/debian/foo"
	release = "2150.8.0"
)

// mustRange parses a VERS range for the fixture inputs.
func mustRange(t *testing.T, versURI string) *lib.Range {
	t.Helper()

	r, err := lib.Parse(versURI)
	require.NoError(t, err)

	return r
}

// assessOne runs the assessor over a single release with a single shipped source.
func assessOne(pkg releasestatus.PackageInput) assessment.PackageStatus {
	out := releasestatus.Assess(releasestatus.Input{
		Releases: []releasestatus.ReleaseInput{{Release: release, Packages: []releasestatus.PackageInput{pkg}}},
	})

	return out[release].Auto.Packages[pkg.SourcePURL]
}

func TestAssess_PerPkgReasons(t *testing.T) {
	t.Parallel()

	debRange := mustRange(t, "vers:deb/<2.0-1")

	tests := []struct {
		name       string
		result     affectedness.Result
		shipped    string
		wantReason assessment.ReleaseStatusReason
		wantBasis  string
	}{
		{
			name: "fix-evidence -> version-fixed, no comparison",
			result: affectedness.Result{
				Outcome:   affectedness.OutcomeFixed,
				Authority: affectedness.AuthorityPkgBuild,
				Basis:     affectedness.BasisFixEvidence,
			},
			shipped:    "1.0-1",
			wantReason: assessment.ReleaseReasonVersionFixed,
		},
		{
			name: "debian not-affected -> declared-not-affected",
			result: affectedness.Result{
				Outcome:   affectedness.OutcomeNotAffected,
				Authority: affectedness.AuthorityDebian,
				Basis:     affectedness.BasisNotAffected,
			},
			shipped:    "1.0-1",
			wantReason: assessment.ReleaseReasonDeclaredNotAffected,
		},
		{
			name: "affected-no-range -> affected-escalated",
			result: affectedness.Result{
				Outcome:   affectedness.OutcomeAffectedNoRange,
				Authority: affectedness.AuthorityDebian,
				Basis:     affectedness.BasisDebianUnfixed,
			},
			shipped:    "1.0-1",
			wantReason: assessment.ReleaseReasonAffectedEscalated,
		},
		{
			name: "undecided -> unknown-escalated",
			result: affectedness.Result{
				Outcome:   affectedness.OutcomeUndecided,
				Authority: affectedness.AuthorityNone,
				Basis:     affectedness.BasisNoAuthority,
			},
			shipped:    "1.0-1",
			wantReason: assessment.ReleaseReasonUnknownEscalated,
			wantBasis:  string(affectedness.BasisNoAuthority),
		},
		{
			name: "range Within -> version-vulnerable",
			result: affectedness.Result{
				Outcome:        affectedness.OutcomeVersionRange,
				Authority:      affectedness.AuthorityDebian,
				Basis:          affectedness.BasisConcreteFixVersion,
				Range:          debRange,
				CompareVersion: "1.5-1",
			},
			shipped:    "1.5-1",
			wantReason: assessment.ReleaseReasonVersionVulnerable,
		},
		{
			name: "range Outside (at edge) -> version-fixed",
			result: affectedness.Result{
				Outcome:        affectedness.OutcomeVersionRange,
				Authority:      affectedness.AuthorityDebian,
				Basis:          affectedness.BasisConcreteFixVersion,
				Range:          debRange,
				CompareVersion: "2.0-1",
			},
			shipped:    "2.0-1",
			wantReason: assessment.ReleaseReasonVersionFixed,
		},
		{
			name: "range Outside -> version-fixed",
			result: affectedness.Result{
				Outcome:        affectedness.OutcomeVersionRange,
				Authority:      affectedness.AuthorityDebian,
				Basis:          affectedness.BasisConcreteFixVersion,
				Range:          debRange,
				CompareVersion: "3.1-9",
			},
			shipped:    "3.1-9",
			wantReason: assessment.ReleaseReasonVersionFixed,
		},
		{
			name: "range eval-Undecidable -> unknown-escalated with distinct basis",
			result: affectedness.Result{
				Outcome:        affectedness.OutcomeVersionRange,
				Authority:      affectedness.AuthorityDebian,
				Basis:          affectedness.BasisConcreteFixVersion,
				Range:          debRange,
				CompareVersion: "!!garbage",
			},
			shipped:    "!!garbage",
			wantReason: assessment.ReleaseReasonUnknownEscalated,
			wantBasis:  releasestatus.BasisEvalUndecidable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := assessOne(releasestatus.PackageInput{
				SourcePURL:     purl,
				ShippedVersion: tt.shipped,
				Affectedness:   tt.result,
			})

			assert.Equal(t, tt.wantReason, got.Reason)
			assert.Equal(t, tt.shipped, got.ShippedVersion)
			if tt.wantBasis != "" {
				assert.Equal(t, tt.wantBasis, got.Basis)
			}
		})
	}
}

func TestAssess_RangeRecordsVulnerableVERS(t *testing.T) {
	t.Parallel()

	got := assessOne(releasestatus.PackageInput{
		SourcePURL:     purl,
		ShippedVersion: "1.5-1",
		Affectedness: affectedness.Result{
			Outcome:        affectedness.OutcomeVersionRange,
			Range:          mustRange(t, "vers:deb/<2.0-1"),
			CompareVersion: "1.5-1",
		},
	})

	assert.Equal(t, assessment.ReleaseReasonVersionVulnerable, got.Reason)
	assert.NotEmpty(t, got.VulnerableRange)
}

func TestAssess_NotShippedReleaseRollsUpToPackageNotShipped(t *testing.T) {
	t.Parallel()

	// A release that ships none of the matched sources carries no per-source entries.
	out := releasestatus.Assess(releasestatus.Input{
		Releases: []releasestatus.ReleaseInput{{Release: release, Packages: nil}},
	})

	decision := out[release]
	assert.Empty(t, decision.Auto.Packages)
	assert.Equal(t, assessment.ReleaseReasonPackageNotShipped, decision.CompositeReason())
	assert.Equal(t, assessment.ReleaseStatusNotAffected, decision.CompositeStatus())
}

func TestAssess_VendoredEscalates(t *testing.T) {
	t.Parallel()

	out := releasestatus.Assess(releasestatus.Input{
		Vendored: true,
		Releases: []releasestatus.ReleaseInput{{Release: release, Packages: []releasestatus.PackageInput{{
			SourcePURL:     purl,
			ShippedVersion: "1.0-1",
			// A deb-path result that would otherwise clear is ignored for vendored matches.
			Affectedness: affectedness.Result{Outcome: affectedness.OutcomeNotAffected},
		}}}},
	})

	got := out[release].Auto.Packages[purl]
	assert.Equal(t, assessment.ReleaseReasonUnknownEscalated, got.Reason)
	assert.True(t, got.Vendored)
	assert.Equal(t, releasestatus.BasisVendoredDeferred, got.Basis)
	assert.True(t, out[release].NeedsEscalation())
}

func TestAssess_RetainsEveryShippedSource(t *testing.T) {
	t.Parallel()

	out := releasestatus.Assess(releasestatus.Input{
		Releases: []releasestatus.ReleaseInput{{Release: release, Packages: []releasestatus.PackageInput{
			{
				SourcePURL:     "pkg:deb/debian/foo",
				ShippedVersion: "1.0-1",
				Affectedness:   affectedness.Result{Outcome: affectedness.OutcomeFixed},
			},
			{
				SourcePURL:     "pkg:deb/debian/bar",
				ShippedVersion: "2.0-1",
				Affectedness:   affectedness.Result{Outcome: affectedness.OutcomeAffectedNoRange},
			},
		}}},
	})

	sources := out[release].Auto.Packages
	require.Len(t, sources, 2)
	assert.Equal(t, assessment.ReleaseReasonVersionFixed, sources["pkg:deb/debian/foo"].Reason)
	assert.Equal(t, assessment.ReleaseReasonAffectedEscalated, sources["pkg:deb/debian/bar"].Reason)
	// Composite leans affected: one presumed-affected source keeps the release affected.
	assert.Equal(t, assessment.ReleaseReasonAffectedEscalated, out[release].CompositeReason())
}
