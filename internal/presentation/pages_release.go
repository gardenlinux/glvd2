package presentation

import (
	"context"
	"fmt"

	"github.com/gardenlinux/glvd2/internal/assessment"
)

type releasePageData struct {
	commonData

	Version string
	Flavors []flavorLink
	CVEs    []cveScopeRow
	Filter  *scopeFilter
}

type flavorLink struct {
	Name string
	URL  string
}

type cveScopeRow struct {
	ID           string
	URL          string
	Affectedness string
	NeedsReview  bool
	Sources      []string
}

// scopeFilterID links the scope table to its pill filter panel.
// There is one scope table per page, so a fixed identifier is sufficient.
const scopeFilterID = "scope-filter"

// Column indices of the filterable scope columns, matching the "scopeRows" table header order.
const (
	scopeStatusColumn = 1
	scopeReviewColumn = 2
)

// filterPill is one option in a filter group. An empty Token clears the group's column filter.
type filterPill struct {
	Label string
	Token string
}

// filterGroup toggles an exact-match search on a single scope table column.
type filterGroup struct {
	Legend string
	Column int
	Pills  []filterPill
}

type scopeFilter struct {
	ID     string
	Groups []filterGroup
}

// buildScopeFilter returns the pill filter for a scope table, or nil when no column offers a useful choice.
// A group is only emitted when its column has at least two distinct values to pick from.
func buildScopeFilter(statusLegend string, rows []cveScopeRow) *scopeFilter {
	var groups []filterGroup

	if g := statusFilterGroup(statusLegend, rows); g != nil {
		groups = append(groups, *g)
	}

	if g := reviewFilterGroup(rows); g != nil {
		groups = append(groups, *g)
	}

	if len(groups) == 0 {
		return nil
	}

	return &scopeFilter{ID: scopeFilterID, Groups: groups}
}

// minScopeFilterOptions is the smallest number of distinct column values that makes a filter
// group worthwhile. With fewer options there is nothing to choose between.
const minScopeFilterOptions = 2

func statusFilterGroup(legend string, rows []cveScopeRow) *filterGroup {
	// Stable display order for the status pills.
	order := []string{
		string(assessment.ReleaseStatusAffected),
		string(assessment.ReleaseStatusFixed),
		string(assessment.ReleaseStatusNotAffected),
		string(assessment.ReleaseStatusUnknown),
	}

	present := make(map[string]bool, len(order))
	for _, row := range rows {
		if row.Affectedness != "" {
			present[row.Affectedness] = true
		}
	}

	// A single value offers no meaningful choice, so skip the group entirely.
	if len(present) < minScopeFilterOptions {
		return nil
	}

	pills := []filterPill{{Label: "All"}}
	for _, token := range order {
		if present[token] {
			pills = append(pills, filterPill{Label: displayLabel(token), Token: token})
		}
	}

	return &filterGroup{Legend: legend, Column: scopeStatusColumn, Pills: pills}
}

func reviewFilterGroup(rows []cveScopeRow) *filterGroup {
	var needed, notNeeded bool

	for _, row := range rows {
		if row.NeedsReview {
			needed = true
		} else {
			notNeeded = true
		}
	}

	if !needed || !notNeeded {
		return nil
	}

	return &filterGroup{
		Legend: "Needs review",
		Column: scopeReviewColumn,
		Pills: []filterPill{
			{Label: "All"},
			{Label: "Yes", Token: "yes"},
			{Label: "No", Token: "no"},
		},
	}
}

type flavorPageData struct {
	commonData

	Version string
	Flavor  string
	CVEs    []cveScopeRow
	Filter  *scopeFilter
}

func (rr *renderRun) writeReleasePage(ctx context.Context, rel Release) error {
	relURL, err := rr.r.urls.Release(rel.Version)
	if err != nil {
		return err
	}

	flavors := make([]flavorLink, 0, len(rel.Flavors))
	for _, fl := range rel.Flavors {
		flURL, urlErr := rr.r.urls.Flavor(rel.Version, fl.Name)
		if urlErr != nil {
			return urlErr
		}

		flavors = append(flavors, flavorLink{Name: fl.Name, URL: flURL})
	}

	rows, err := rr.buildCVEScopeRows(rel.CVEs)
	if err != nil {
		return err
	}

	data := releasePageData{
		commonData: commonData{
			Title:   "Release " + rel.Version,
			Section: releasesSection,
			Breadcrumbs: []breadcrumb{
				{Label: releasesLabel, URL: rr.r.urls.Releases()},
				{Label: rel.Version, URL: relURL},
			},
		},
		Version: rel.Version,
		Flavors: flavors,
		CVEs:    rows,
		Filter:  buildScopeFilter("Release status", rows),
	}

	if err = rr.writePage(relURL, "release", &data); err != nil {
		return err
	}

	for _, fl := range rel.Flavors {
		if err = ctx.Err(); err != nil {
			return err
		}

		if err = rr.writeFlavorPage(rel.Version, relURL, fl); err != nil {
			return fmt.Errorf("flavor %q: %w", fl.Name, err)
		}
	}

	return nil
}

func (rr *renderRun) buildCVEScopeRows(cves []ScopedCVE) ([]cveScopeRow, error) {
	rows := make([]cveScopeRow, 0, len(cves))
	for _, sc := range cves {
		cveURL, err := rr.r.urls.CVE(sc.ID)
		if err != nil {
			return nil, err
		}

		rows = append(rows, cveScopeRow{
			ID:           sc.ID,
			URL:          cveURL,
			Affectedness: string(sc.Affectedness),
			NeedsReview:  sc.NeedsReview,
			Sources:      sc.SourcePackages,
		})
	}

	return rows, nil
}

func (rr *renderRun) writeFlavorPage(version, relURL string, fl Flavor) error {
	flURL, err := rr.r.urls.Flavor(version, fl.Name)
	if err != nil {
		return err
	}

	rows, err := rr.buildCVEScopeRows(fl.CVEs)
	if err != nil {
		return err
	}

	for i := range rows {
		rows[i].URL += "#release-" + version
	}

	data := flavorPageData{
		commonData: commonData{
			Title:   "Release " + version + " / " + fl.Name,
			Section: releasesSection,
			Breadcrumbs: []breadcrumb{
				{Label: releasesLabel, URL: rr.r.urls.Releases()},
				{Label: version, URL: relURL},
				{Label: fl.Name, URL: flURL},
			},
		},
		Version: version,
		Flavor:  fl.Name,
		CVEs:    rows,
		Filter:  buildScopeFilter("Flavor status", rows),
	}

	return rr.writePage(flURL, "flavor", &data)
}
