package presentation

import "github.com/gardenlinux/glvd2/internal/assessment"

type overviewData struct {
	commonData

	BuildSHA      string
	BuildSHAShort string
	GeneratedAt   string
	Counts        databaseCounts
	Releases      []releaseRow
}

type releaseRow struct {
	Version          string
	URL              string
	FlavorsAvailable bool
	Affected         int
	Fixed            int
	NotAffected      int
	Unknown          int
	NeedsReview      int
}

type releasesPageData struct {
	commonData

	Releases []releaseRow
}

func (rr *renderRun) writeReleasesPage(releases []Release) error {
	rows := make([]releaseRow, 0, len(releases))
	for _, rel := range releases {
		relURL, err := rr.r.urls.Release(rel.Version)
		if err != nil {
			return err
		}

		rows = append(rows, buildReleaseRow(rel, relURL))
	}

	data := releasesPageData{
		commonData: commonData{
			Title:       "Maintained releases",
			Section:     releasesSection,
			Breadcrumbs: []breadcrumb{{Label: releasesLabel, URL: rr.r.urls.Releases()}},
		},
		Releases: rows,
	}

	return rr.writePage(rr.r.urls.Releases(), releasesSection, &data)
}

func (rr *renderRun) writeOverviewPage(releases []Release) error {
	rows := make([]releaseRow, 0, len(releases))
	for _, rel := range releases {
		relURL, err := rr.r.urls.Release(rel.Version)
		if err != nil {
			return err
		}

		rows = append(rows, buildReleaseRow(rel, relURL))
	}

	data := overviewData{
		commonData: commonData{
			Title:   "Garden Linux Vulnerability Database",
			Section: "home",
		},
		BuildSHA:      rr.buildSHA,
		BuildSHAShort: shortSHA(rr.buildSHA),
		GeneratedAt:   rr.generatedAt,
		Counts:        rr.agg.counts,
		Releases:      rows,
	}

	return rr.writePage(rr.r.urls.Root(), "overview", &data)
}

func buildReleaseRow(rel Release, relURL string) releaseRow {
	row := releaseRow{
		Version:          rel.Version,
		URL:              relURL,
		FlavorsAvailable: len(rel.Flavors) > 0,
	}

	for _, sc := range rel.CVEs {
		if sc.NeedsReview {
			row.NeedsReview++
		}

		switch sc.Affectedness {
		case assessment.ReleaseStatusAffected:
			row.Affected++
		case assessment.ReleaseStatusFixed:
			row.Fixed++
		case assessment.ReleaseStatusNotAffected:
			row.NotAffected++
		case assessment.ReleaseStatusUnknown:
			row.Unknown++
		}
	}

	return row
}
