package screening_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/gardenlinux/glvd2/internal/cvelistv5"
	"github.com/gardenlinux/glvd2/internal/debsectracker"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/glrd"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/inventory"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/packages"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/version"
	"github.com/gardenlinux/glvd2/internal/glmap"
	"github.com/gardenlinux/glvd2/internal/model/debtriage"
	"github.com/gardenlinux/glvd2/internal/repository"
	"github.com/gardenlinux/glvd2/internal/screening"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// curatedRules builds the curated GL-specific mapping used by the service test.
func curatedRules(t *testing.T) glmap.Rules {
	t.Helper()

	rules, err := glmap.NewFromRules([]glmap.Rule{{
		TargetPURL: "pkg:deb/gardenlinux/curated-target",
		InputPURLs: []string{"pkg:golang/example.com/curated"},
	}})
	require.NoError(t, err)

	return rules
}

// fakeDST is a stub DebianVerdictLookup backed by an in-memory map.
type fakeDST struct {
	entries map[string]*debsectracker.TriageEntry
	err     error
}

func (f fakeDST) GetTriageEntryFromDB(_ context.Context, cveID string) (*debsectracker.TriageEntry, error) {
	if f.err != nil {
		return nil, f.err
	}

	e, ok := f.entries[cveID]
	if !ok {
		return nil, sql.ErrNoRows
	}

	return e, nil
}

// testInventory builds a membership set containing the given source names.
func testInventory(t *testing.T, sources ...string) inventory.Set {
	t.Helper()

	pkgs := make([]packages.Package, 0, len(sources))
	for _, src := range sources {
		pkgs = append(pkgs, packages.Package{Name: src, Source: src, Namespace: "debian"})
	}

	acc := inventory.NewAccumulator(
		inventory.WithMinPURLs(0),
		inventory.WithInReleaseFetch(
			func(_ context.Context, _ version.GardenLinuxRelease) ([]packages.Package, error) {
				return pkgs, nil
			},
		),
	)

	require.NoError(t, acc.MissingSBOMSet(t.Context(), glrd.Release{Name: "test"}))

	set, err := acc.Result()
	require.NoError(t, err)

	return set
}

func vendoredRules(t *testing.T) glmap.Rules {
	t.Helper()

	rules, err := glmap.NewFromRules([]glmap.Rule{{
		TargetPURL: "pkg:deb/gardenlinux/vendored-parent",
		InputPURLs: []string{"pkg:golang/example.com/vendored"},
	}})
	require.NoError(t, err)

	return rules
}

func debianEntry(status debtriage.StatusType, pkgs ...string) *debsectracker.TriageEntry {
	entry := &debsectracker.TriageEntry{Triage: repository.DebianTriage{Status: status}}
	for _, p := range pkgs {
		entry.AffectedPackages = append(entry.AffectedPackages,
			repository.DebianTriageAffectedPackage{PackageName: p})
	}

	return entry
}

func idsWithPURL(purls ...string) cvelistv5.IDsForCVEs {
	return cvelistv5.IDsForCVEs{
		"CVE-2026-0001": &cvelistv5.Identifiers{PackageURLs: purls},
	}
}

func newRecord(state assessment.CVEState) assessment.Record {
	return assessment.Record{ID: "CVE-2026-0001", Upstream: assessment.UpstreamData{State: state}}
}

func TestService_Screen(t *testing.T) {
	t.Parallel()

	// These cases target the input assembly; not the decision, which is covered by TestScreen_Rules.
	tests := []struct {
		name        string
		state       assessment.CVEState
		ids         cvelistv5.IDsForCVEs
		vendored    bool
		inventory   []string
		debian      *debsectracker.TriageEntry
		wantReason  assessment.TriageReason
		wantMatched []string
	}{
		{
			name:       "rejected state maps to rejected-upstream",
			state:      assessment.CVEStateRejected,
			wantReason: assessment.TriageReasonRejectedUpstream,
		},
		{
			name:        "curated PURL resolves to its GL target",
			ids:         idsWithPURL("pkg:golang/example.com/curated"),
			wantReason:  assessment.TriageReasonAffectsGardenLinuxPackage,
			wantMatched: []string{"pkg:deb/gardenlinux/curated-target"},
		},
		{
			name:        "vendored PURL resolves to its parent",
			ids:         idsWithPURL("pkg:golang/example.com/vendored"),
			vendored:    true,
			wantReason:  assessment.TriageReasonAffectsVendoredDependency,
			wantMatched: []string{"pkg:deb/gardenlinux/vendored-parent"},
		},
		{
			name:       "DST NOT-FOR-US maps to debian-not-for-us",
			debian:     debianEntry(debtriage.StatusNotForUs),
			wantReason: assessment.TriageReasonDebianNotForUs,
		},
		{
			name:        "shipped Debian package canonicalizes and matches inventory",
			inventory:   []string{"bar"},
			debian:      debianEntry(debtriage.StatusProcessed, "bar"),
			wantReason:  assessment.TriageReasonAffectsDebianPackage,
			wantMatched: []string{"pkg:deb/debian/bar"},
		},
		{
			name:        "unshipped Debian package records its resolved PURL",
			inventory:   []string{"bar"},
			debian:      debianEntry(debtriage.StatusProcessed, "foo"),
			wantReason:  assessment.TriageReasonDebianPackageNotShipped,
			wantMatched: []string{"pkg:deb/debian/foo"},
		},
		{
			name:       "missing DST verdict is not an error",
			wantReason: assessment.TriageReasonAwaitingDebian,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			inv := testInventory(t, tt.inventory...)

			vendored, err := glmap.NewFromRules(nil)
			require.NoError(t, err)
			if tt.vendored {
				vendored = vendoredRules(t)
			}

			debian := fakeDST{entries: map[string]*debsectracker.TriageEntry{}}
			if tt.debian != nil {
				debian.entries["CVE-2026-0001"] = tt.debian
			}

			s := screening.NewService(curatedRules(t), vendored, inv, debian, tt.ids)

			got, err := s.Screen(t.Context(), newRecord(tt.state))
			require.NoError(t, err)

			assert.Equal(t, tt.wantReason, got.AutoTriage.Reason)
			assert.Equal(t, tt.wantMatched, got.Matched)
		})
	}
}

// TestService_Screen_DebianLookupError verifies a non-ErrNoRows lookup failure is propagated.
func TestService_Screen_DebianLookupError(t *testing.T) {
	t.Parallel()

	emptyRules, err := glmap.NewFromRules(nil)
	require.NoError(t, err)

	wantErr := errors.New("db unavailable")
	s := screening.NewService(
		curatedRules(t),
		emptyRules,
		testInventory(t, "bar"),
		fakeDST{err: wantErr},
		nil,
	)

	_, err = s.Screen(t.Context(), newRecord(assessment.CVEStatePublished))
	require.ErrorIs(t, err, wantErr)
}
