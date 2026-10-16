package affectedness_test

import (
	"testing"

	"github.com/gardenlinux/glvd2/internal/affectedness"
	"github.com/gardenlinux/glvd2/internal/debsectracker"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/pkgbuild"
	"github.com/gardenlinux/glvd2/internal/model/cve_v5"
	"github.com/git-pkgs/vers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveDebian(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		analysis  pkgbuild.Analysis
		verdict   debsectracker.Verdict
		cve       *cve_v5.CVEV5
		outcome   affectedness.Outcome
		authority affectedness.Authority
		basis     affectedness.Basis
		extra     func(t *testing.T, res affectedness.Result)
	}{
		{
			name:      "fixed",
			analysis:  analysis(pkgbuild.ProvenancePatchedFromDebian),
			verdict:   debsectracker.Verdict{Reason: debsectracker.ReasonFixed, FixedVersion: "1.1.1n-1"},
			outcome:   affectedness.OutcomeVersionRange,
			authority: affectedness.AuthorityDebian,
			basis:     affectedness.BasisConcreteFixVersion,
			extra: func(t *testing.T, res affectedness.Result) {
				t.Helper()
				require.NotNil(t, res.Range)
				assert.Equal(t, "vers:deb/<1.1.1n-1", vers.ToVersString(res.Range, "deb"))
				assert.Equal(t, testVersion, res.CompareVersion)
				// Below the fix is vulnerable; at/above is fixed.
				assert.Equal(t, "deb", res.Range.Scheme)
			},
		},
		{
			name:      "not-affected",
			analysis:  analysis(pkgbuild.ProvenanceTakenFromTesting),
			verdict:   debsectracker.Verdict{Reason: debsectracker.ReasonNotAffected},
			outcome:   affectedness.OutcomeNotAffected,
			authority: affectedness.AuthorityDebian,
			basis:     affectedness.BasisNotAffected,
			extra:     func(t *testing.T, res affectedness.Result) { t.Helper(); assert.Nil(t, res.Range) },
		},
		{
			name:      "version-less unfixed",
			analysis:  analysis(pkgbuild.ProvenanceTakenFromTesting),
			verdict:   debsectracker.Verdict{Reason: debsectracker.ReasonUnfixed},
			outcome:   affectedness.OutcomeAffectedNoRange,
			authority: affectedness.AuthorityDebian,
			basis:     affectedness.BasisDebianUnfixed,
			extra:     func(t *testing.T, res affectedness.Result) { t.Helper(); assert.Nil(t, res.Range) },
		},
		{
			name:      "version-less end-of-life",
			analysis:  analysis(pkgbuild.ProvenanceTakenFromTesting),
			verdict:   debsectracker.Verdict{Reason: debsectracker.ReasonEndOfLife},
			outcome:   affectedness.OutcomeAffectedNoRange,
			authority: affectedness.AuthorityDebian,
			basis:     affectedness.BasisDebianUnfixed,
			extra:     func(t *testing.T, res affectedness.Result) { t.Helper(); assert.Nil(t, res.Range) },
		},
		{
			// Debian undecided -> upstream authority is deferred, so escalate.
			name:      "undecided escalates while upstream is deferred",
			analysis:  analysis(pkgbuild.ProvenanceTakenFromTesting),
			verdict:   debsectracker.Verdict{Reason: debsectracker.ReasonUndetermined},
			outcome:   affectedness.OutcomeUndecided,
			authority: affectedness.AuthorityNone,
			basis:     affectedness.BasisNoAuthority,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			res := resolve(t, tt.analysis, tt.verdict, tt.cve)

			assert.Equal(t, tt.outcome, res.Outcome)
			assert.Equal(t, tt.authority, res.Authority)
			assert.Equal(t, tt.basis, res.Basis)
			if tt.extra != nil {
				tt.extra(t, res)
			}
		})
	}
}

func TestResolveBuiltFromUpstreamEscalates(t *testing.T) {
	t.Parallel()

	a := analysis(pkgbuild.ProvenanceBuiltFromUpstream)
	a.Signals.UpstreamVersion = "1.9.0"

	// A self-built source ignores Debian; with upstream deferred it escalates.
	res := resolve(t, a,
		debsectracker.Verdict{Reason: debsectracker.ReasonFixed, FixedVersion: "9.9-9"},
		nil)

	assert.Equal(t, affectedness.OutcomeUndecided, res.Outcome)
	assert.Equal(t, affectedness.AuthorityNone, res.Authority)
	assert.Equal(t, affectedness.BasisNoAuthority, res.Basis)
	assert.Nil(t, res.Range)
}

func TestResolveVerdictLookupErrors(t *testing.T) {
	t.Parallel()

	// A deb-comparable lineage consults Debian, so the lookup error surfaces.
	builds := fakeBuilds{analyses: map[string]pkgbuild.Analysis{
		"openssl\x00" + testVersion: analysis(pkgbuild.ProvenanceTakenFromTesting),
	}}
	r := affectedness.NewResolver(builds, fakeVerdicts{err: errStub})

	_, err := r.Resolve(t.Context(), affectedness.Request{
		CVEID:          testCVE,
		SourcePURL:     testSource,
		ShippedVersion: testVersion,
	})
	require.ErrorIs(t, err, errStub)
}
