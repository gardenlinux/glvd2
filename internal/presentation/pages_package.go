package presentation

import (
	"strings"

	"github.com/gardenlinux/glvd2/internal/assessment"
)

type packagesPageData struct {
	commonData

	Packages []packageListRow
}

type packageListRow struct {
	Name        string
	Namespace   string
	URL         string
	Total       int
	Affected    int
	NeedsReview int
}

type packagePageData struct {
	commonData

	Name               string
	Namespaces         []string
	SourcePackagePURLs []string
	CVEs               []packageCVERow
}

type packageCVERow struct {
	ID                string
	SourcePackagePURL string
	CVEURL            string
	Release           string
	ReleaseURL        string
	IsManual          bool
	Status            string
	Reason            string
	NeedsReview       bool
	Basis             string
	BasisWhy          string
	ShippedVersion    string
	VulnerableRange   string
	Authority         string
	Provenance        string
	Vendored          bool
	Component         string
	Justification     string
}

func (rr *renderRun) writePackagesPage(pkgs []Package) error {
	rows := make([]packageListRow, 0, len(pkgs))

	for _, pkg := range pkgs {
		url, err := rr.r.urls.Package(pkg.Name)
		if err != nil {
			return err
		}

		rows = append(rows, buildPackageListRow(pkg, url))
	}

	data := packagesPageData{
		commonData: commonData{
			Title:       packagesLabel,
			Section:     packagesSection,
			Breadcrumbs: []breadcrumb{{Label: packagesLabel, URL: rr.r.urls.Packages()}},
		},
		Packages: rows,
	}

	return rr.writePage(rr.r.urls.Packages(), packagesSection, &data)
}

func buildPackageListRow(pkg Package, url string) packageListRow {
	seen := make(map[string]struct{})
	affected := make(map[string]struct{})
	review := make(map[string]struct{})

	for _, c := range pkg.CVEs {
		seen[c.ID] = struct{}{}

		if c.Status == assessment.ReleaseStatusAffected {
			affected[c.ID] = struct{}{}
		}

		if c.NeedsReview {
			review[c.ID] = struct{}{}
		}
	}

	return packageListRow{
		Name:        pkg.Name,
		Namespace:   strings.Join(pkg.Namespaces, ", "),
		URL:         url,
		Total:       len(seen),
		Affected:    len(affected),
		NeedsReview: len(review),
	}
}

func (rr *renderRun) writePackagePage(pkg Package) error {
	url, err := rr.r.urls.Package(pkg.Name)
	if err != nil {
		return err
	}

	rows, err := rr.buildPackageCVERows(pkg.CVEs)
	if err != nil {
		return err
	}

	data := packagePageData{
		commonData: commonData{
			Title:   pkg.Name,
			Section: packagesSection,
			Breadcrumbs: []breadcrumb{
				{Label: packagesLabel, URL: rr.r.urls.Packages()},
				{Label: pkg.Name, URL: url},
			},
		},
		Name:               pkg.Name,
		Namespaces:         pkg.Namespaces,
		SourcePackagePURLs: pkg.SourcePackagePURLs,
		CVEs:               rows,
	}

	return rr.writePage(url, "package", &data)
}

func (rr *renderRun) buildPackageCVERows(cves []PackageCVE) ([]packageCVERow, error) {
	rows := make([]packageCVERow, 0, len(cves))

	for _, c := range cves {
		cveURL, err := rr.r.urls.CVE(c.ID)
		if err != nil {
			return nil, err
		}

		relURL, err := rr.r.urls.Release(c.Release)
		if err != nil {
			return nil, err
		}

		rows = append(rows, packageCVERow{
			ID:                c.ID,
			SourcePackagePURL: c.SourcePackagePURL,
			CVEURL:            cveURL + "#release-" + c.Release,
			Release:           c.Release,
			ReleaseURL:        relURL,
			IsManual:          c.IsManual,
			Status:            string(c.Status),
			Reason:            string(c.Reason),
			NeedsReview:       c.NeedsReview,
			Basis:             c.Basis,
			BasisWhy:          c.BasisWhy,
			ShippedVersion:    c.ShippedVersion,
			VulnerableRange:   c.VulnerableRange,
			Authority:         c.Authority,
			Provenance:        c.Provenance,
			Vendored:          c.Vendored,
			Component:         c.Component,
			Justification:     c.Justification,
		})
	}

	return rows, nil
}
