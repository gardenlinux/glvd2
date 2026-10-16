package affectedness_test

import (
	"context"
	"errors"
	"testing"

	"github.com/gardenlinux/glvd2/internal/affectedness"
	"github.com/gardenlinux/glvd2/internal/debsectracker"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/pkgbuild"
	"github.com/gardenlinux/glvd2/internal/model/cve_v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeBuilds is a stubbed BuildAnalyzer keyed by "name\x00version".
type fakeBuilds struct {
	analyses map[string]pkgbuild.Analysis
	err      error
}

func (f fakeBuilds) Analyze(_ context.Context, name, version string) (pkgbuild.Analysis, error) {
	if f.err != nil {
		return pkgbuild.Analysis{}, f.err
	}

	return f.analyses[name+"\x00"+version], nil
}

// fakeVerdicts is a stubbed DebianVerdicts returning a single fixed verdict.
type fakeVerdicts struct {
	verdict debsectracker.Verdict
	err     error
}

func (f fakeVerdicts) Lookup(_, _ string) (debsectracker.Verdict, error) {
	return f.verdict, f.err
}

const (
	testCVE     = "CVE-2024-1234"
	testSource  = "pkg:deb/debian/openssl"
	testVersion = "1.1.1k-1"
)

var errStub = errors.New("stub failure")

func analysis(prov pkgbuild.Provenance, fixed ...string) pkgbuild.Analysis {
	a := pkgbuild.Analysis{PkgName: "openssl", Version: testVersion, Provenance: prov}
	for _, id := range fixed {
		a.FixedCVEs = append(a.FixedCVEs, pkgbuild.FixedCVE{ID: id, Kind: pkgbuild.EvidenceKindPatchFilename})
	}

	return a
}

func resolve(t *testing.T, a pkgbuild.Analysis, v debsectracker.Verdict, cve *cve_v5.CVEV5) affectedness.Result {
	t.Helper()

	builds := fakeBuilds{analyses: map[string]pkgbuild.Analysis{"openssl\x00" + testVersion: a}}
	r := affectedness.NewResolver(builds, fakeVerdicts{verdict: v})

	res, err := r.Resolve(t.Context(), affectedness.Request{
		CVEID:          testCVE,
		SourcePURL:     testSource,
		ShippedVersion: testVersion,
		CVE:            cve,
	})
	require.NoError(t, err)

	return res
}

func TestResolveFixEvidence(t *testing.T) {
	t.Parallel()

	// Fix-evidence wins regardless of provenance or the Debian verdict.
	res := resolve(t,
		analysis(pkgbuild.ProvenanceBuiltFromUpstream, testCVE),
		debsectracker.Verdict{Reason: debsectracker.ReasonFixed, FixedVersion: "9.9-9"},
		nil,
	)

	assert.Equal(t, affectedness.OutcomeFixed, res.Outcome)
	assert.Equal(t, affectedness.AuthorityPkgBuild, res.Authority)
	assert.Equal(t, affectedness.BasisFixEvidence, res.Basis)
	assert.Nil(t, res.Range)
}

func TestResolveFixEvidenceAbsentFallsThrough(t *testing.T) {
	t.Parallel()

	// Fix-evidence for a different CVE must not clear this one.
	res := resolve(t,
		analysis(pkgbuild.ProvenanceTakenFromTesting, "CVE-2000-0001"),
		debsectracker.Verdict{Reason: debsectracker.ReasonFixed, FixedVersion: "1.1.1n-1"},
		nil,
	)

	assert.Equal(t, affectedness.OutcomeVersionRange, res.Outcome)
	assert.Equal(t, affectedness.AuthorityDebian, res.Authority)
}

func TestResolveProvenanceUnknownEscalates(t *testing.T) {
	t.Parallel()

	// An unreadable lineage escalates even when Debian would decide not-affected.
	res := resolve(t,
		analysis(pkgbuild.ProvenanceUnknown),
		debsectracker.Verdict{Reason: debsectracker.ReasonNotAffected},
		nil,
	)

	assert.Equal(t, affectedness.OutcomeUndecided, res.Outcome)
	assert.Equal(t, affectedness.AuthorityNone, res.Authority)
	assert.Equal(t, affectedness.BasisNoAuthority, res.Basis)
}

func TestResolveInvalidPURLErrors(t *testing.T) {
	t.Parallel()

	r := affectedness.NewResolver(fakeBuilds{}, fakeVerdicts{})

	_, err := r.Resolve(t.Context(), affectedness.Request{
		CVEID:          testCVE,
		SourcePURL:     "not-a-purl",
		ShippedVersion: testVersion,
	})
	require.Error(t, err)
}

func TestResolveBuildAnalyzeErrors(t *testing.T) {
	t.Parallel()

	r := affectedness.NewResolver(fakeBuilds{err: errStub}, fakeVerdicts{})

	_, err := r.Resolve(t.Context(), affectedness.Request{
		CVEID:          testCVE,
		SourcePURL:     testSource,
		ShippedVersion: testVersion,
	})
	require.ErrorIs(t, err, errStub)
}

func TestResolveNoAuthority(t *testing.T) {
	t.Parallel()

	res := resolve(t,
		analysis(pkgbuild.ProvenanceTakenFromTesting),
		debsectracker.Verdict{Reason: debsectracker.ReasonNoEntry},
		nil,
	)

	assert.Equal(t, affectedness.OutcomeUndecided, res.Outcome)
	assert.Equal(t, affectedness.AuthorityNone, res.Authority)
	assert.Equal(t, affectedness.BasisNoAuthority, res.Basis)
}
