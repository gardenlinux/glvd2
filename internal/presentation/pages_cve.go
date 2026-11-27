package presentation

import (
	"fmt"
	"maps"
	"slices"

	"github.com/gardenlinux/glvd2/internal/assessment"
)

type cvePageData struct {
	commonData

	ID                   string
	State                string
	Rejected             bool
	PublishedAt          string
	FirstSeenAt          string
	Description          string
	CVSSv3               string
	CVSSv4               string
	CWEs                 []string
	References           []string
	RelevanceExplanation string
	AutoStatus           string
	AutoReason           string
	ManualTriage         string
	ManualJustification  string
	Notes                string
	Matched              []packageLink
	Releases             []cveReleaseRow
	AffectednessSummary  cveAffectednessSummary
	ExternalSources      []externalLink
}

type cveReleaseRow struct {
	Version          string
	ReleaseURL       string
	Historical       bool
	Affectedness     string
	Explanation      string
	NeedsReview      bool
	Sources          []packageLink
	FlavorsAvailable bool
	Flavors          []cveFlavorRow
	Packages         []packageRow
}

type cveFlavorRow struct {
	Name         string
	URL          string
	ScopeStatus  string
	Affectedness string
}

type packageRow struct {
	Source          string
	Name            string
	URL             string
	IsManual        bool
	Status          string
	Reason          string
	Basis           string
	BasisWhy        string
	ShippedVersion  string
	VulnerableRange string
	Authority       string
	Provenance      string
	Vendored        bool
	Component       string
	Justification   string
}

func (rr *renderRun) writeCVEPage(rec assessment.Record) error {
	cveURL, err := rr.r.urls.CVE(rec.ID)
	if err != nil {
		return err
	}

	packageURLs, err := rr.cvePackageURLs(rec)
	if err != nil {
		return err
	}

	releases, err := rr.buildCVEReleaseRows(rec, packageURLs)
	if err != nil {
		return err
	}

	matched, err := packageLinks(rec.Screening.Matched, packageURLs)
	if err != nil {
		return err
	}

	data := cvePageData{
		commonData: commonData{
			Title:   rec.ID,
			Section: cvesSection,
			Breadcrumbs: []breadcrumb{
				{Label: cvesLabel, URL: rr.r.urls.CVEs()},
				{Label: rec.ID, URL: cveURL},
			},
		},
		ID:                   rec.ID,
		State:                string(rec.Upstream.State),
		Rejected:             rec.Upstream.State == assessment.CVEStateRejected,
		Description:          rec.Upstream.Description,
		CWEs:                 rec.Upstream.CWEs,
		References:           rec.Upstream.References,
		RelevanceExplanation: relevanceExplanation(rec),
		AutoStatus:           relevanceText(rec.Screening.AutoTriage.Status()),
		AutoReason:           string(rec.Screening.AutoTriage.Reason),
		ManualTriage:         string(rec.Manual.ManualTriage.Status),
		ManualJustification:  rec.Manual.ManualTriage.Justification,
		Notes:                rec.Manual.Notes,
		Matched:              matched,
		Releases:             releases,
		AffectednessSummary:  buildCVEAffectednessSummary(releases),
		ExternalSources:      cveExternalSources(rec.ID),
	}

	if !rec.Upstream.PublishedAt.IsZero() {
		data.PublishedAt = rec.Upstream.PublishedAt.Format(dateFormat)
	}

	data.FirstSeenAt = formatDate(rec.Meta.FirstSeenAt)

	if v := rec.Upstream.CVSSv3; v != nil {
		data.CVSSv3 = fmt.Sprintf("%.1f %s", v.Score, v.Vector)
	}

	if v := rec.Upstream.CVSSv4; v != nil {
		data.CVSSv4 = fmt.Sprintf("%.1f %s", v.Score, v.Vector)
	}

	return rr.writePage(cveURL, "cve", &data)
}

func (rr *renderRun) buildCVEReleaseRows(
	rec assessment.Record,
	packageURLs map[string]string,
) ([]cveReleaseRow, error) {
	versions := slices.Collect(maps.Keys(rec.Releases))
	slices.SortFunc(versions, compareReleaseVersionsDesc)

	rows := make([]cveReleaseRow, 0, len(versions))

	for _, version := range versions {
		if err := validatePathSegment(version); err != nil {
			return nil, fmt.Errorf("release version %q: %w", version, err)
		}

		rd := rec.Releases[version]
		_, maintained := rr.agg.maintainedSet[version]
		sc := projectCVEToRelease(rec, version)
		sources, srcErr := packageLinks(sc.SourcePackages, packageURLs)
		if srcErr != nil {
			return nil, srcErr
		}

		row := cveReleaseRow{
			Version:      version,
			Historical:   !maintained,
			Affectedness: string(sc.Affectedness),
			Explanation:  releaseExplanation(rd),
			NeedsReview:  sc.NeedsReview,
			Sources:      sources,
			Packages:     buildPackageRows(rd),
		}

		for i := range row.Packages {
			pkg := &row.Packages[i]

			name, _, nameErr := packageNameNamespace(pkg.Source)
			if nameErr != nil {
				return nil, nameErr
			}

			pkg.Name = name
			pkg.URL = packageURLs[name]
		}

		if maintained {
			relURL, err := rr.r.urls.Release(version)
			if err != nil {
				return nil, err
			}

			row.ReleaseURL = relURL
		}

		row.FlavorsAvailable = maintained && rr.inv.HasFlavors(version)
		if row.FlavorsAvailable {
			for _, fl := range rr.inv.Flavors(version) {
				flURL, err := rr.r.urls.Flavor(version, fl)
				if err != nil {
					return nil, err
				}

				fsc, err := projectCVEToFlavor(rec, version, fl, rr.inv)
				if err != nil {
					return nil, err
				}

				row.Flavors = append(row.Flavors, cveFlavorRow{
					Name:         fl,
					URL:          flURL,
					ScopeStatus:  string(fsc.Status),
					Affectedness: string(fsc.Affectedness),
				})
			}
		}

		rows = append(rows, row)
	}

	return rows, nil
}

func buildPackageRows(rd assessment.ReleaseDecision) []packageRow {
	var rows []packageRow

	overridden := make(map[string]struct{}, len(rd.Manual.Packages))
	for key, ov := range rd.Manual.Packages {
		if !ov.IsEmpty() {
			overridden[key] = struct{}{}
		}
	}

	for _, key := range slices.Sorted(maps.Keys(rd.Auto.Packages)) {
		// A manual decision replaces the automated finding for the same package.
		if _, ok := overridden[key]; ok {
			continue
		}

		ps := rd.Auto.Packages[key]

		rows = append(rows, packageRow{
			Source:          key,
			Status:          string(ps.Reason.Status()),
			Reason:          string(ps.Reason),
			Basis:           ps.Basis,
			BasisWhy:        ps.BasisWhy,
			ShippedVersion:  ps.ShippedVersion,
			VulnerableRange: ps.VulnerableRange,
			Authority:       ps.Authority,
			Provenance:      ps.Provenance,
			Vendored:        ps.Vendored,
			Component:       ps.Component,
		})
	}

	for _, key := range slices.Sorted(maps.Keys(rd.Manual.Packages)) {
		ov := rd.Manual.Packages[key]
		if ov.IsEmpty() {
			continue
		}

		rows = append(rows, packageRow{
			Source:        key,
			IsManual:      true,
			Status:        string(ov.Status),
			Justification: ov.Justification,
		})
	}

	return rows
}
