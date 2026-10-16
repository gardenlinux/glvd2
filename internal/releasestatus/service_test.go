package releasestatus_test

import (
	"context"
	"errors"
	"testing"

	"github.com/gardenlinux/glvd2/internal/affectedness"
	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/gardenlinux/glvd2/internal/model/cve_v5"
	"github.com/gardenlinux/glvd2/internal/releasestatus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	fooIdentity    = "pkg:deb/debian/foo"
	fooVersioned   = "pkg:deb/debian/foo@1.0-1"
	barIdentity    = "pkg:deb/debian/bar"
	barVersioned   = "pkg:deb/debian/bar@2.0-1"
	releaseA       = "2150.8.0"
	releaseB       = "1877.26"
	assessedCVE    = "CVE-2024-1234"
	notShippedPURL = "pkg:deb/debian/absent"
)

// fakeIndex serves a fixed per-release shipped-versions map.
type fakeIndex struct {
	releases []string
	// shipped maps releaseKey -> identity PURL -> versioned PURL.
	shipped map[string]map[string]string
	err     error
}

func (f fakeIndex) Releases() []string { return f.releases }

func (f fakeIndex) Lookup(releaseKey, canonicalSourcePURL string) (string, bool, error) {
	if f.err != nil {
		return "", false, f.err
	}
	versioned, ok := f.shipped[releaseKey][canonicalSourcePURL]

	return versioned, ok, nil
}

// fakeResolver records the requests it receives and returns a canned result per source.
type fakeResolver struct {
	results  map[string]affectedness.Result
	requests []affectedness.Request
	err      error
}

func (f *fakeResolver) Resolve(_ context.Context, req affectedness.Request) (affectedness.Result, error) {
	f.requests = append(f.requests, req)
	if f.err != nil {
		return affectedness.Result{}, f.err
	}

	return f.results[req.SourcePURL], nil
}

func relevantRecord(matched ...string) assessment.Record {
	return assessment.Record{
		ID: assessedCVE,
		Screening: assessment.ScreeningResult{
			AutoTriage: assessment.AutoTriage{Reason: assessment.TriageReasonAffectsDebianPackage},
			Matched:    matched,
		},
	}
}

func TestService_Assess_PopulatesPerReleaseFromResolver(t *testing.T) {
	t.Parallel()

	index := fakeIndex{
		releases: []string{releaseA, releaseB},
		shipped: map[string]map[string]string{
			releaseA: {fooIdentity: fooVersioned, barIdentity: barVersioned},
			releaseB: {fooIdentity: fooVersioned},
		},
	}
	resolver := &fakeResolver{results: map[string]affectedness.Result{
		fooIdentity: {Outcome: affectedness.OutcomeFixed, Authority: affectedness.AuthorityPkgBuild},
		barIdentity: {Outcome: affectedness.OutcomeAffectedNoRange, Authority: affectedness.AuthorityDebian},
	}}

	s := releasestatus.NewService(resolver, index)

	out, err := s.Assess(context.Background(), relevantRecord(fooIdentity, barIdentity), &cve_v5.CVEV5{})
	require.NoError(t, err)

	// releaseA ships both sources; releaseB ships only foo.
	relA := out[releaseA]
	require.Len(t, relA.Auto.Packages, 2)
	assert.Equal(t, assessment.ReleaseReasonVersionFixed, relA.Auto.Packages[fooIdentity].Reason)
	assert.Equal(t, "1.0-1", relA.Auto.Packages[fooIdentity].ShippedVersion)
	assert.Equal(t, assessment.ReleaseReasonAffectedEscalated, relA.Auto.Packages[barIdentity].Reason)

	relB := out[releaseB]
	require.Len(t, relB.Auto.Packages, 1)
	assert.Equal(t, assessment.ReleaseReasonVersionFixed, relB.Auto.Packages[fooIdentity].Reason)
	_, hasBar := relB.Auto.Packages[barIdentity]
	assert.False(t, hasBar)

	// The resolver received the shipped version for each (release, shipped source) pair.
	require.Len(t, resolver.requests, 3)
	for _, req := range resolver.requests {
		assert.Equal(t, assessedCVE, req.CVEID)
		assert.NotEmpty(t, req.ShippedVersion)
		assert.NotNil(t, req.CVE)
	}
}

func TestService_Assess_NotShippedSourceIsOmitted(t *testing.T) {
	t.Parallel()

	index := fakeIndex{
		releases: []string{releaseA},
		shipped:  map[string]map[string]string{releaseA: {fooIdentity: fooVersioned}},
	}
	resolver := &fakeResolver{results: map[string]affectedness.Result{
		fooIdentity: {Outcome: affectedness.OutcomeFixed},
	}}

	s := releasestatus.NewService(resolver, index)

	out, err := s.Assess(context.Background(), relevantRecord(fooIdentity, notShippedPURL), &cve_v5.CVEV5{})
	require.NoError(t, err)

	rel := out[releaseA]
	require.Len(t, rel.Auto.Packages, 1)
	_, present := rel.Auto.Packages[notShippedPURL]
	assert.False(t, present)
	// The resolver is never asked about a source the release does not ship.
	require.Len(t, resolver.requests, 1)
	assert.Equal(t, fooIdentity, resolver.requests[0].SourcePURL)
}

func TestService_Assess_VendoredSkipsResolver(t *testing.T) {
	t.Parallel()

	index := fakeIndex{
		releases: []string{releaseA},
		shipped:  map[string]map[string]string{releaseA: {fooIdentity: fooVersioned}},
	}
	resolver := &fakeResolver{}

	rec := relevantRecord(fooIdentity)
	rec.Screening.AutoTriage.Reason = assessment.TriageReasonAffectsVendoredDependency

	s := releasestatus.NewService(resolver, index)

	out, err := s.Assess(context.Background(), rec, &cve_v5.CVEV5{})
	require.NoError(t, err)

	got := out[releaseA].Auto.Packages[fooIdentity]
	assert.Equal(t, assessment.ReleaseReasonUnknownEscalated, got.Reason)
	assert.True(t, got.Vendored)
	assert.Equal(t, "1.0-1", got.ShippedVersion)
	// Vendored matches never reach the deb-path resolver while component analysis is deferred.
	assert.Empty(t, resolver.requests)
}

func TestService_Assess_PropagatesResolverError(t *testing.T) {
	t.Parallel()

	index := fakeIndex{
		releases: []string{releaseA},
		shipped:  map[string]map[string]string{releaseA: {fooIdentity: fooVersioned}},
	}
	resolver := &fakeResolver{err: errors.New("some error")}

	s := releasestatus.NewService(resolver, index)

	_, err := s.Assess(context.Background(), relevantRecord(fooIdentity), &cve_v5.CVEV5{})
	require.Error(t, err)
}

func TestService_Assess_PropagatesIndexError(t *testing.T) {
	t.Parallel()

	index := fakeIndex{releases: []string{releaseA}, err: errors.New("another error")}
	resolver := &fakeResolver{}

	s := releasestatus.NewService(resolver, index)

	_, err := s.Assess(context.Background(), relevantRecord(fooIdentity), &cve_v5.CVEV5{})
	require.Error(t, err)
}
