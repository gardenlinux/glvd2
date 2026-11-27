package presentation

import (
	"fmt"
	"maps"
	"slices"

	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/flavorinventory"
)

// projectCVEToRelease projects one record into a release scope.
func projectCVEToRelease(rec assessment.Record, release string) ScopedCVE {
	rd, ok := rec.Releases[release]
	if !ok {
		return ScopedCVE{ID: rec.ID, Status: ScopeStatusNotAssessed}
	}

	// A manual decision can mark this release affected even if its SBOM does not contain
	// the package. Unlike automatic assessment, this roll-up does not check shipment for
	// manual entries. Flavor projections exclude entries absent from the flavor inventory.
	return ScopedCVE{
		ID:             rec.ID,
		SourcePackages: contributingSourcePackages(rd),
		Status:         ScopeStatusAssessed,
		Affectedness:   rd.CompositeStatus(),
		NeedsReview:    anyNeedsReview(rd.EffectiveReasons()),
	}
}

// projectCVEToFlavor projects one record into a covered flavor scope.
func projectCVEToFlavor(
	rec assessment.Record,
	release, flavor string,
	inv flavorinventory.Inventory,
) (ScopedCVE, error) {
	rd, ok := rec.Releases[release]
	if !ok {
		return ScopedCVE{ID: rec.ID, Status: ScopeStatusNotAssessed}, nil
	}

	decisionForFlavor, err := scopeDecisionToFlavor(rd, release, flavor, inv)
	if err != nil {
		return ScopedCVE{}, fmt.Errorf(
			"restricting %s decision for release %q flavor %q: %w",
			rec.ID,
			release,
			flavor,
			err,
		)
	}

	sourcePkgs := contributingSourcePackages(decisionForFlavor)
	if len(sourcePkgs) == 0 {
		return ScopedCVE{ID: rec.ID, Status: ScopeStatusOutsideScope}, nil
	}

	return ScopedCVE{
		ID:             rec.ID,
		SourcePackages: sourcePkgs,
		Status:         ScopeStatusAssessed,
		Affectedness:   decisionForFlavor.CompositeStatus(),
		NeedsReview:    anyNeedsReview(decisionForFlavor.EffectiveReasons()),
	}, nil
}

// scopeDecisionToFlavor returns a decision whose auto and manual package maps keep only the keys
// whose source package PURL is a member of the flavor, using namespace-tolerant matching.
func scopeDecisionToFlavor(
	rd assessment.ReleaseDecision,
	release, flavor string,
	inv flavorinventory.Inventory,
) (assessment.ReleaseDecision, error) {
	auto := make(map[string]assessment.PackageStatus)
	for key, ps := range rd.Auto.Packages {
		in, err := inv.Contains(release, flavor, key)
		if err != nil {
			return assessment.ReleaseDecision{}, err
		}
		if in {
			auto[key] = ps
		}
	}

	manual := make(map[string]assessment.PackageOverride)
	for key, override := range rd.Manual.Packages {
		in, err := inv.Contains(release, flavor, key)
		if err != nil {
			return assessment.ReleaseDecision{}, err
		}
		if in {
			manual[key] = override
		}
	}

	return assessment.ReleaseDecision{
		Auto:   assessment.AutoReleaseStatus{Packages: auto},
		Manual: assessment.ManualReleaseStatus{Packages: manual},
	}, nil
}

// contributingSourcePackages returns the sorted union of the decision's contributing auto
// source-package keys and its non-empty manual override keys.
// Auto packages the release does not ship did not contribute to the result.
func contributingSourcePackages(rd assessment.ReleaseDecision) []string {
	keys := make(map[string]struct{}, len(rd.Auto.Packages)+len(rd.Manual.Packages))
	for key, ps := range rd.Auto.Packages {
		if ps.Reason == assessment.ReleaseReasonPackageNotShipped {
			continue
		}
		keys[key] = struct{}{}
	}
	for key, override := range rd.Manual.Packages {
		if !override.IsEmpty() {
			keys[key] = struct{}{}
		}
	}
	if len(keys) == 0 {
		return nil
	}

	return slices.Sorted(maps.Keys(keys))
}

// anyNeedsReview reports whether any effective per-package reason warrants escalation.
func anyNeedsReview(reasons map[string]assessment.ReleaseStatusReason) bool {
	for _, reason := range reasons {
		if reason.NeedsEscalation() {
			return true
		}
	}

	return false
}
