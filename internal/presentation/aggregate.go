package presentation

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/flavorinventory"
	"github.com/gardenlinux/glvd2/internal/purl"
)

// aggregator collects listings and database statistics in one walk of the assessment store.
type aggregator struct {
	inv           flavorinventory.Inventory
	maintainedSet map[string]struct{}
	releases      map[string]*releaseAccumulator
	counts        databaseCounts
	undecided     []cveEntry
	packages      map[string]*packageAccumulator
}

// releaseAccumulator collects the listing entries for one maintained release during the walk.
type releaseAccumulator struct {
	version    string
	flavors    []string
	cves       []ScopedCVE
	flavorCVEs map[string][]ScopedCVE
}

// packageAccumulator collects the per-CVE decisions for one source package during the walk.
type packageAccumulator struct {
	cves []PackageCVE
}

// newAggregator seeds the maintained releases and their flavors from the inventory.
func newAggregator(inv flavorinventory.Inventory, maintained []string) *aggregator {
	agg := &aggregator{
		inv:           inv,
		maintainedSet: make(map[string]struct{}, len(maintained)),
		releases:      make(map[string]*releaseAccumulator, len(maintained)),
		counts:        newDatabaseCounts(),
		packages:      make(map[string]*packageAccumulator),
	}

	for _, version := range maintained {
		agg.maintainedSet[version] = struct{}{}
		agg.releases[version] = &releaseAccumulator{
			version:    version,
			flavors:    inv.Flavors(version),
			flavorCVEs: make(map[string][]ScopedCVE),
		}
	}

	return agg
}

// add retains lightweight listing entries from rec, not the full record.
func (a *aggregator) add(rec assessment.Record) error {
	a.counts.add(rec)

	status := rec.GetGlobalStatus()
	if status == assessment.StatusUndecided {
		a.undecided = append(a.undecided, cveEntry{
			ID:          rec.ID,
			FirstSeenAt: rec.Meta.FirstSeenAt,
			PublishedAt: rec.Upstream.PublishedAt,
		})
	}

	if status != assessment.StatusRelevant {
		return nil
	}

	for version, ra := range a.releases {
		rd, ok := rec.Releases[version]
		if !ok {
			continue
		}
		ra.cves = append(ra.cves, projectCVEToRelease(rec, version))
		a.addPackages(rec.ID, version, rd)

		if len(ra.flavors) == 0 {
			continue
		}
		for _, flavor := range ra.flavors {
			sc, err := projectCVEToFlavor(rec, version, flavor, a.inv)
			if err != nil {
				return err
			}
			if sc.Status != ScopeStatusAssessed {
				continue
			}
			ra.flavorCVEs[flavor] = append(ra.flavorCVEs[flavor], sc)
		}
	}

	return nil
}

// addPackages records one evidence row per package in the decision. A manual override replaces
// the automated finding for the same source package, so the superseded automated row is dropped.
func (a *aggregator) addPackages(cveID, version string, rd assessment.ReleaseDecision) {
	effectiveReasons := rd.EffectiveReasons()
	overridden := make(map[string]struct{}, len(rd.Manual.Packages))
	for srcPkgPURL, ov := range rd.Manual.Packages {
		if !ov.IsEmpty() {
			overridden[srcPkgPURL] = struct{}{}
		}
	}

	for _, srcPkgPURL := range slices.Sorted(maps.Keys(rd.Auto.Packages)) {
		if _, ok := overridden[srcPkgPURL]; ok {
			continue
		}

		ps := rd.Auto.Packages[srcPkgPURL]
		a.addPackageCVE(srcPkgPURL, PackageCVE{
			ID:              cveID,
			Release:         version,
			Status:          ps.Reason.Status(),
			Reason:          ps.Reason,
			NeedsReview:     ps.Reason.NeedsEscalation(),
			ShippedVersion:  ps.ShippedVersion,
			VulnerableRange: ps.VulnerableRange,
			Authority:       ps.Authority,
			Provenance:      ps.Provenance,
			Basis:           ps.Basis,
			BasisWhy:        ps.BasisWhy,
			Vendored:        ps.Vendored,
			Component:       ps.Component,
		})
	}

	for _, srcPkgPURL := range slices.Sorted(maps.Keys(rd.Manual.Packages)) {
		ov := rd.Manual.Packages[srcPkgPURL]
		if ov.IsEmpty() {
			continue
		}
		a.addPackageCVE(srcPkgPURL, PackageCVE{
			ID:            cveID,
			Release:       version,
			IsManual:      true,
			Status:        ov.Status,
			NeedsReview:   effectiveReasons[srcPkgPURL].NeedsEscalation(),
			Justification: ov.Justification,
		})
	}
}

func (a *aggregator) addPackageCVE(sourcePkgPURL string, entry PackageCVE) {
	pa, ok := a.packages[sourcePkgPURL]
	if !ok {
		pa = &packageAccumulator{}
		a.packages[sourcePkgPURL] = pa
	}

	entry.SourcePackagePURL = sourcePkgPURL
	pa.cves = append(pa.cves, entry)
}

// finish returns the aggregated releases, ordered numerically,
// with their CVE and flavor listings sorted deterministically.
func (a *aggregator) finish() []Release {
	// All CVE tables show the newest CVE IDs first.
	slices.SortFunc(a.undecided, func(x, y cveEntry) int {
		return compareCVEIDs(y.ID, x.ID)
	})

	versions := slices.Collect(maps.Keys(a.releases))
	slices.SortFunc(versions, compareReleaseVersionsDesc)

	out := make([]Release, 0, len(versions))
	for _, version := range versions {
		ra := a.releases[version]
		rel := Release{
			Version: ra.version,
			CVEs:    sortedScopedCVEs(ra.cves),
		}
		if len(ra.flavors) > 0 {
			rel.Flavors = make([]Flavor, 0, len(ra.flavors))
			for _, flavor := range ra.flavors {
				rel.Flavors = append(rel.Flavors, Flavor{
					Name: flavor,
					CVEs: sortedScopedCVEs(ra.flavorCVEs[flavor]),
				})
			}
		}
		out = append(out, rel)
	}

	return out
}

// sortedScopedCVEs returns a copy of the entries ordered newest first by CVE year and sequence.
func sortedScopedCVEs(in []ScopedCVE) []ScopedCVE {
	out := slices.Clone(in)
	slices.SortFunc(out, func(a, b ScopedCVE) int {
		return compareCVEIDs(b.ID, a.ID)
	})

	return out
}

// finishPackages groups namespace variants by source name without losing their evidence identities.
func (a *aggregator) finishPackages() ([]Package, error) {
	byName := make(map[string]*Package, len(a.packages))
	for _, srcPkgPURL := range slices.Sorted(maps.Keys(a.packages)) {
		name, namespace, err := packageNameNamespace(srcPkgPURL)
		if err != nil {
			return nil, err
		}

		pkg, ok := byName[name]
		if !ok {
			pkg = &Package{Name: name}
			byName[name] = pkg
		}

		pkg.SourcePackagePURLs = append(pkg.SourcePackagePURLs, srcPkgPURL)
		if namespace != "" && !slices.Contains(pkg.Namespaces, namespace) {
			pkg.Namespaces = append(pkg.Namespaces, namespace)
		}
		pkg.CVEs = append(pkg.CVEs, a.packages[srcPkgPURL].cves...)
	}

	out := make([]Package, 0, len(byName))
	for _, name := range slices.Sorted(maps.Keys(byName)) {
		pkg := byName[name]
		slices.Sort(pkg.Namespaces)
		pkg.CVEs = sortedPackageCVEs(pkg.CVEs)
		out = append(out, *pkg)
	}

	return out, nil
}

// packageNameNamespace derives the display name and namespace from a source package identity PURL.
// A malformed PURL would yield an unusable page path, so it is reported as an error.
func packageNameNamespace(srcPkgPURL string) (string, string, error) {
	name, err := purl.NameOf(srcPkgPURL)
	if err != nil {
		return "", "", fmt.Errorf("deriving package name from %q: %w", srcPkgPURL, err)
	}

	if name == "" {
		return "", "", fmt.Errorf("package identity %q yields an empty name", srcPkgPURL)
	}

	namespace, err := purl.NamespaceOf(srcPkgPURL)
	if err != nil {
		return "", "", fmt.Errorf("deriving package namespace from %q: %w", srcPkgPURL, err)
	}

	return name, namespace, nil
}

// sortedPackageCVEs orders newest CVE first, then by release and source package PURL.
func sortedPackageCVEs(in []PackageCVE) []PackageCVE {
	out := slices.Clone(in)
	slices.SortFunc(out, func(a, b PackageCVE) int {
		if c := compareCVEIDs(b.ID, a.ID); c != 0 {
			return c
		}
		if c := compareReleaseVersions(a.Release, b.Release); c != 0 {
			return c
		}
		return strings.Compare(a.SourcePackagePURL, b.SourcePackagePURL)
	})

	return out
}
