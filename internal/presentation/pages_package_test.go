package presentation_test

import (
	"path/filepath"
	"testing"

	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/gardenlinux/glvd2/internal/presentation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPackages_NamespaceVariantsSharePageAndKeepEvidenceIdentities(t *testing.T) {
	t.Parallel()

	const version = "2000.1"
	const name = "gtk+3.0"
	first := relevantRecord("CVE-2024-1001", map[string]assessment.ReleaseDecision{
		version: autoDecision(map[string]assessment.PackageStatus{
			glID(name): autoPkg(assessment.ReleaseReasonVersionFixed),
		}),
	})
	second := relevantRecord("CVE-2024-1002", map[string]assessment.ReleaseDecision{
		version: autoDecision(map[string]assessment.PackageStatus{
			debID(name): autoPkg(assessment.ReleaseReasonVersionVulnerable),
		}),
	})

	res := render(t, inventory(t, nil), []string{version}, first, second)

	listing := pageTableRecords(t, res.OutDir, presentation.SiteURLs{}.Packages(), "Package", "CVEs")
	require.Len(t, listing, 1)

	for field, want := range map[string]string{
		"Package": name, "Namespace": "debian, gardenlinux", "CVEs": "2", "Affected": "1", "Needs review": "0",
	} {
		assert.Equal(t, want, listing[0][field], field)
	}

	page := parseHTML(t, readFile(t, filepath.Join(res.OutDir, packagePath(name))))
	assert.Contains(t, page.content(), glID(name))
	assert.Contains(t, page.content(), debID(name))

	rows := pageTableRecords(t, res.OutDir, packagePath(name), "CVE", "Decision")
	require.Len(t, rows, 2)

	for _, row := range rows {
		identity := map[string]string{first.ID: glID(name), second.ID: debID(name)}[row["CVE"]]
		require.NotEmpty(t, identity)

		assert.Contains(t, row["Decision"], identity)
	}

	for _, rec := range []assessment.Record{first, second} {
		doc := parseHTML(t, readCVEPage(t, res.OutDir, rec.ID))

		anchors := doc.all("a")

		links := make([]string, 0, len(anchors))
		for _, link := range anchors {
			links = append(links, link.attrs["href"])
		}

		assert.Contains(t, links, "../../packages/gtk+3.0/index.html")
	}

	reversed := render(t, inventory(t, nil), []string{version}, second, first)

	for _, rec := range []assessment.Record{first, second} {
		page := "cves/" + rec.ID + "/index.html"
		assert.Equal(t, pageTableRecords(t, res.OutDir, page, "Source package", "Decision source"),
			pageTableRecords(t, reversed.OutDir, page, "Source package", "Decision source"))
	}

	assert.Equal(t, rows, pageTableRecords(t, reversed.OutDir, packagePath(name), "CVE", "Decision"))
}

func TestPackages_ExcludeNotRelevantAndHistoricalReleases(t *testing.T) {
	t.Parallel()

	const version = "2000.1"
	rec := relevantRecord("CVE-2024-1001", map[string]assessment.ReleaseDecision{
		version: autoDecision(map[string]assessment.PackageStatus{
			glID("glibc"): autoPkg(assessment.ReleaseReasonVersionVulnerable),
		}),
		"184.0": autoDecision(map[string]assessment.PackageStatus{
			glID("glibc"): autoPkg(assessment.ReleaseReasonVersionFixed),
		}),
	})

	notrel := notRelevantRecord("CVE-2024-1002", map[string]assessment.ReleaseDecision{
		version: autoDecision(map[string]assessment.PackageStatus{
			glID("openssl"): autoPkg(assessment.ReleaseReasonVersionVulnerable),
		}),
	})

	res := render(t, inventory(t, nil), []string{version}, rec, notrel)

	listing := pageTableRecords(t, res.OutDir, presentation.SiteURLs{}.Packages(), "Package", "CVEs")
	require.Len(t, listing, 1)

	for field, want := range map[string]string{
		"Package": "glibc", "Namespace": "gardenlinux", "CVEs": "1", "Affected": "1", "Needs review": "0",
	} {
		assert.Equal(t, want, listing[0][field], field)
	}

	rows := pageTableRecords(t, res.OutDir, packagePath("glibc"), "CVE", "Release")
	require.Len(t, rows, 1)

	assert.Equal(t, rec.ID, rows[0]["CVE"])
	assert.Equal(t, version, rows[0]["Release"])
	assert.Equal(t, "Affected", rows[0]["Status"])

	assertFileNotExists(t, filepath.Join(res.OutDir, packagePath("openssl")))
}

func TestPackages_ManualOverrideReplacesAutomatedRow(t *testing.T) {
	t.Parallel()

	auto := assessment.PackageStatus{
		Reason:          assessment.ReleaseReasonUnknownEscalated,
		Basis:           "vendored-deferred",
		BasisWhy:        "Component version cannot be established.",
		ShippedVersion:  "3.4.5-1",
		VulnerableRange: "< 3.4.6",
		Authority:       "debian",
		Provenance:      "security-tracker",
		Vendored:        true,
		Component:       "openssl",
	}

	rec := relevantRecord("CVE-2024-1001", map[string]assessment.ReleaseDecision{
		"2000.1": decision(
			map[string]assessment.PackageStatus{glID("glibc"): auto},
			map[string]assessment.PackageOverride{glID("glibc"): {
				Status: assessment.ReleaseStatusNotAffected, Justification: "Feature is disabled.",
			}},
		),
	})

	res := render(t, inventory(t, nil), []string{"2000.1"}, rec)

	const decisionCol, basisCol = "Decision", "Basis"

	path := packagePath("glibc")
	doc := parseHTML(t, readFile(t, filepath.Join(res.OutDir, path)))

	table := tableWithHeaders(t, doc, decisionCol, basisCol)
	rows := tableRecords(t, table)

	// The automated finding is superseded by the manual override, so only the manual row remains.
	require.Len(t, rows, 1, path)

	assert.Equal(t, "Manual", rows[0][decisionCol], path)
	assert.Equal(t, "Not affected", rows[0]["Status"], path)
	assert.Equal(t, "Feature is disabled.", rows[0]["Justification"], path)

	for _, field := range []string{"Shipped version", "Vulnerable range", basisCol, "Explanation"} {
		assert.Empty(t, rows[0][field], "%s in %s", field, path)
	}
}

func TestPackages_ManualOverrideNeedsReview(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		status      assessment.ReleaseStatus
		needsReview string
		reviewCount string
	}{
		{assessment.ReleaseStatusAffected, "No", "0"},
		{assessment.ReleaseStatusFixed, "No", "0"},
		{assessment.ReleaseStatusNotAffected, "No", "0"},
		{assessment.ReleaseStatusUnknown, "Yes", "1"},
	} {
		t.Run(string(tc.status), func(t *testing.T) {
			t.Parallel()

			for _, auto := range []struct {
				name   string
				reason assessment.ReleaseStatusReason
			}{
				{name: "manual only"},
				{name: "replaces confirmed finding", reason: assessment.ReleaseReasonVersionVulnerable},
				{name: "replaces escalated finding", reason: assessment.ReleaseReasonUnknownEscalated},
			} {
				t.Run(auto.name, func(t *testing.T) {
					t.Parallel()

					var packages map[string]assessment.PackageStatus

					if auto.reason != "" {
						packages = map[string]assessment.PackageStatus{glID("glibc"): autoPkg(auto.reason)}
					}

					rec := relevantRecord("CVE-2024-1001", map[string]assessment.ReleaseDecision{
						"2000.1": decision(packages, map[string]assessment.PackageOverride{
							glID("glibc"): override(tc.status),
						}),
					})

					res := render(t, inventory(t, nil), []string{"2000.1"}, rec)

					rows := pageTableRecords(t, res.OutDir, packagePath("glibc"), "CVE", "Decision")
					require.Len(t, rows, 1)

					assert.Equal(t, "Manual", rows[0]["Decision"])
					assert.Equal(t, tc.needsReview, rows[0]["Needs review"])
					assert.Empty(t, rows[0]["Reason"], "representative reasons are not automated evidence")

					listing := pageTableRecords(t, res.OutDir, presentation.SiteURLs{}.Packages(), "Package", "CVEs")
					require.Len(t, listing, 1)
					assert.Equal(t, tc.reviewCount, listing[0]["Needs review"])
				})
			}
		})
	}
}

func TestPackages_PreserveAutomatedEvidenceWithoutOverride(t *testing.T) {
	t.Parallel()

	pkg := assessment.PackageStatus{
		Reason:          assessment.ReleaseReasonUnknownEscalated,
		Basis:           "vendored-deferred",
		BasisWhy:        "Component version cannot be established.",
		ShippedVersion:  "3.4.5-1",
		VulnerableRange: "< 3.4.6",
		Authority:       "debian",
		Provenance:      "security-tracker",
		Vendored:        true,
		Component:       "openssl",
	}

	rec := relevantRecord("CVE-2024-1001", map[string]assessment.ReleaseDecision{
		"2000.1": autoDecision(map[string]assessment.PackageStatus{glID("glibc"): pkg}),
	})

	res := render(t, inventory(t, nil), []string{"2000.1"}, rec)

	const decisionCol, basisCol = "Decision", "Basis"

	path := packagePath("glibc")
	doc := parseHTML(t, readFile(t, filepath.Join(res.OutDir, path)))

	table := tableWithHeaders(t, doc, decisionCol, basisCol)
	rows := tableRecords(t, table)
	require.Len(t, rows, 1, path)

	assert.Equal(t, "Automated", rows[0][decisionCol], path)
	assert.Equal(t, "Unknown", rows[0]["Status"], path)
	assert.NotEmpty(t, rows[0]["Reason"], path)
	assert.NotEmpty(t, rows[0][basisCol], path)

	for field, want := range map[string]string{
		"Explanation": pkg.BasisWhy, "Shipped version": pkg.ShippedVersion,
		"Vulnerable range": pkg.VulnerableRange, "Authority": pkg.Authority,
		"Provenance": pkg.Provenance, "Vendored component": pkg.Component,
	} {
		assert.Equal(t, want, rows[0][field], "%s in %s", field, path)
	}

	assert.Contains(t, doc.content(), glID("glibc"), path)
}
