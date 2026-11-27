package presentation_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCVE_AffectednessSummarizesOnlyRecordedMaintainedResults(t *testing.T) {
	t.Parallel()

	rec := relevantRecord("CVE-2024-1001", map[string]assessment.ReleaseDecision{
		"100.0": autoDecision(map[string]assessment.PackageStatus{
			glID("historical"): autoPkg(assessment.ReleaseReasonUnknownEscalated),
		}),
		"2000.1": autoDecision(map[string]assessment.PackageStatus{
			glID("glibc"):   autoPkg(assessment.ReleaseReasonVersionVulnerable),
			glID("openssl"): autoPkg(assessment.ReleaseReasonUnknownEscalated),
		}),
		"2000.2": autoDecision(map[string]assessment.PackageStatus{
			glID("glibc"): autoPkg(assessment.ReleaseReasonVersionFixed),
		}),
		"2000.3": decision(
			map[string]assessment.PackageStatus{glID("glibc"): autoPkg(assessment.ReleaseReasonVersionVulnerable)},
			map[string]assessment.PackageOverride{glID("glibc"): override(assessment.ReleaseStatusNotAffected)},
		),
		"2000.4": autoDecision(map[string]assessment.PackageStatus{
			glID("glibc"): autoPkg(assessment.ReleaseReasonUnknownEscalated),
		}),
	})

	res := render(t, inventory(t, nil),
		[]string{"2000.5", "2000.4", "2000.3", "2000.2", "2000.1"}, rec)

	doc := parseHTML(t, readCVEPage(t, res.OutDir, rec.ID))

	affectedness := htmlElement(t, doc, "", "aria-labelledby", "affectedness-heading")
	rows := tableRecords(t, tableWithHeaders(t, affectedness, "Release", "Status", "Needs review"))
	require.Len(t, rows, 4)
	assert.ElementsMatch(t, []string{"2000.1", "2000.2", "2000.3", "2000.4"}, recordValues(rows, "Release"))

	statuses := map[string]string{
		"2000.1": "Affected",
		"2000.2": "Fixed",
		"2000.3": "Not affected",
		"2000.4": "Unknown",
	}
	for _, row := range rows {
		assert.Equal(t, statuses[row["Release"]], row["Status"])
		htmlElement(t, affectedness, "a", "href", "#release-"+row["Release"])
	}

	assert.ElementsMatch(t, []string{"Yes", "No", "No", "Yes"}, recordValues(rows, "Needs review"))

	historical := htmlElement(t, doc, "", "aria-labelledby", "release-100.0")
	for _, link := range historical.all("a") {
		assert.NotContains(t, link.attrs["href"], "releases/100.0/")
	}

	assertFileNotExists(t, filepath.Join(res.OutDir, packagePath("historical")))
	assertFileNotExists(t, filepath.Join(res.OutDir, releasePath("100.0")))

	listed := pageTableRecords(t, res.OutDir, "index.html", "Release")
	assert.NotContains(t, recordValues(listed, "Release"), "100.0")
}

func TestCVE_ExternalSourcesAndRejectedNotice(t *testing.T) {
	t.Parallel()

	for _, state := range []assessment.CVEState{assessment.CVEStatePublished, assessment.CVEStateRejected, ""} {
		t.Run(string(state), func(t *testing.T) {
			t.Parallel()

			rec := relevantRecord("CVE-2024-1001", nil)
			rec.Upstream.State = state
			rec.Upstream.Description = "Upstream description."
			rec.Manual.ManualTriage = assessment.ManualTriage{
				Status: assessment.StatusRelevant, Justification: "Keep tracking this issue.",
			}
			res := render(t, inventory(t, nil), nil, rec)

			doc := parseHTML(t, readCVEPage(t, res.OutDir, rec.ID))

			sources := htmlElement(t, doc, "", "aria-label", "External sources")

			links := make(map[string]string)
			for _, link := range sources.all("a") {
				links[link.content()] = link.attrs["href"]
			}

			assert.Equal(t, map[string]string{
				"Debian Security Tracker":  "https://security-tracker.debian.org/tracker/CVE-2024-1001",
				"NVD":                      "https://nvd.nist.gov/vuln/detail/CVE-2024-1001",
				"GitHub Advisory Database": "https://github.com/advisories?query=CVE-2024-1001",
			}, links)

			assert.Contains(t, doc.content(), "Keep tracking this issue.")
			assert.Contains(t, doc.content(), rec.Upstream.Description)
			affectedness := htmlElement(t, doc, "", "aria-labelledby", "affectedness-heading")
			for _, body := range affectedness.all("tbody") {
				assert.Empty(t, body.all("tr"))
			}

			if state == assessment.CVEStateRejected {
				notice := htmlElement(t, doc, "", "aria-labelledby", "rejected-heading")
				assert.Contains(t, notice.content(), "Rejected upstream")
			} else {
				for _, node := range doc.all("") {
					assert.NotEqual(t, "rejected-heading", node.attrs["id"])
				}
			}
		})
	}
}

func TestCVE_PackageLinksDoNotPointToUnpublishedPages(t *testing.T) {
	t.Parallel()

	decisions := map[string]assessment.ReleaseDecision{
		"100.0": autoDecision(map[string]assessment.PackageStatus{
			glID("historical"): autoPkg(assessment.ReleaseReasonVersionVulnerable),
		}),
		"2000.1": decision(
			map[string]assessment.PackageStatus{glID("glibc"): autoPkg(assessment.ReleaseReasonVersionVulnerable)},
			map[string]assessment.PackageOverride{glID("manual-only"): override(assessment.ReleaseStatusFixed)},
		),
	}
	for _, relevant := range []bool{true, false} {
		t.Run(map[bool]string{true: "relevant", false: "not-relevant"}[relevant], func(t *testing.T) {
			t.Parallel()

			rec := relevantRecord("CVE-2024-1001", decisions)

			if !relevant {
				rec = notRelevantRecord(rec.ID, decisions)
			}

			rec.Screening.Matched = []string{debID("glibc"), glID("unlisted")}
			res := render(t, inventory(t, nil), []string{"2000.1"}, rec)

			doc := parseHTML(t, readCVEPage(t, res.OutDir, rec.ID))

			var links []string
			for _, link := range doc.all("a") {
				target := link.attrs["href"]
				if strings.Contains(target, "/packages/") && !strings.HasSuffix(target, "/packages/index.html") {
					links = append(links, target)
				}
			}
			assert.NotContains(t, links, "../../packages/historical/index.html")
			assert.NotContains(t, links, "../../packages/unlisted/index.html")

			if relevant {
				assert.Contains(t, links, "../../packages/glibc/index.html")
				assert.Contains(t, links, "../../packages/manual-only/index.html")
				assertFileExists(t, filepath.Join(res.OutDir, packagePath("manual-only")))
			} else {
				assert.Empty(t, links)
			}
		})
	}
}

func TestCVE_ManualStatusDoesNotInventVersionEvidence(t *testing.T) {
	t.Parallel()

	rec := relevantRecord("CVE-2024-1001", map[string]assessment.ReleaseDecision{
		"2000.1": decision(nil, map[string]assessment.PackageOverride{
			glID("glibc"): {Status: assessment.ReleaseStatusAffected, Justification: "Confirmed by maintainer."},
		}),
	})

	res := render(t, inventory(t, nil), []string{"2000.1"}, rec)

	doc := parseHTML(t, readCVEPage(t, res.OutDir, rec.ID))

	details := htmlElement(t, doc, "", "aria-labelledby", "release-2000.1")

	rows := tableRecords(t, tableWithHeaders(t, details, "Decision source", "Status"))
	require.Len(t, rows, 1)

	assert.Equal(t, "Manual", rows[0]["Decision source"])
	assert.Equal(t, "Affected", rows[0]["Status"])
	assert.Equal(t, "Confirmed by maintainer.", rows[0]["Justification"])

	for _, field := range []string{"Shipped version", "Vulnerable range", "Evidence basis", "Explanation"} {
		assert.Empty(t, rows[0][field], field)
	}
}

func TestCVE_ManualOverrideReplacesAutomatedRow(t *testing.T) {
	t.Parallel()

	rec := relevantRecord("CVE-2024-1001", map[string]assessment.ReleaseDecision{
		"2000.1": decision(
			map[string]assessment.PackageStatus{
				glID("glibc"):   autoPkg(assessment.ReleaseReasonVersionVulnerable),
				glID("openssl"): autoPkg(assessment.ReleaseReasonVersionFixed),
			},
			map[string]assessment.PackageOverride{
				glID("glibc"): {Status: assessment.ReleaseStatusNotAffected, Justification: "Feature disabled."},
			},
		),
	})

	res := render(t, inventory(t, nil), []string{"2000.1"}, rec)

	doc := parseHTML(t, readCVEPage(t, res.OutDir, rec.ID))

	details := htmlElement(t, doc, "", "aria-labelledby", "release-2000.1")
	rows := tableRecords(t, tableWithHeaders(t, details, "Decision source", "Status"))

	// glibc's vulnerable automated finding is superseded by its manual override, so only the
	// manual row remains. openssl has no override and keeps its automated row.
	require.Len(t, rows, 2)

	assert.ElementsMatch(t, []string{"Manual", "Automated"}, recordValues(rows, "Decision source"))

	for _, row := range rows {
		switch row["Decision source"] {
		case "Manual":
			assert.Equal(t, "Not affected", row["Status"])
		case "Automated":
			assert.Equal(t, "Fixed", row["Status"])
		}
	}
}

func TestCVE_ScreeningDecisionsRemainSeparateFromAffectedness(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		reason     assessment.TriageReason
		manual     assessment.ManualTriage
		autoStatus string
	}{
		{
			name: "Debian package", reason: assessment.TriageReasonAffectsDebianPackage,
			autoStatus: "Relevant",
		},
		{
			name: "Garden Linux package", reason: assessment.TriageReasonAffectsGardenLinuxPackage,
			autoStatus: "Relevant",
		},
		{
			name: "vendored dependency", reason: assessment.TriageReasonAffectsVendoredDependency,
			autoStatus: "Relevant",
		},
		{
			name: "rejected", reason: assessment.TriageReasonRejectedUpstream,
			autoStatus: "Not relevant",
		},
		{
			name: "awaiting Debian", reason: assessment.TriageReasonAwaitingDebian,
			autoStatus: "Undecided",
		},
		{
			name: "unrecognized reason", reason: "future-reason",
			autoStatus: "Undecided",
		},
		{
			name:   "manual inclusion",
			reason: assessment.TriageReasonRejectedUpstream,
			manual: assessment.ManualTriage{
				Status:        assessment.StatusRelevant,
				Justification: "Track related issue.",
			},
			autoStatus: "Not relevant",
		},
		{
			name: "manual exclusion", reason: assessment.TriageReasonAffectsDebianPackage,
			manual: assessment.ManualTriage{
				Status: assessment.StatusNotRelevant, Justification: "The <feature> is disabled.",
			},
			autoStatus: "Relevant",
		},
		{
			name: "manual without justification", reason: assessment.TriageReasonAffectsDebianPackage,
			manual:     assessment.ManualTriage{Status: assessment.StatusNotRelevant},
			autoStatus: "Relevant",
		},
		{
			name: "justification without decision", reason: assessment.TriageReasonAffectsDebianPackage,
			manual:     assessment.ManualTriage{Justification: "Unfinished review."},
			autoStatus: "Relevant",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rec := relevantRecord("CVE-2024-1001", map[string]assessment.ReleaseDecision{
				"2000.1": autoDecision(map[string]assessment.PackageStatus{
					glID("glibc"): autoPkg(assessment.ReleaseReasonVersionFixed),
				}),
			})
			rec.Screening.AutoTriage.Reason = tc.reason
			rec.Manual.ManualTriage = tc.manual
			res := render(t, inventory(t, nil), []string{"2000.1"}, rec)

			doc := parseHTML(t, readCVEPage(t, res.OutDir, rec.ID))

			affectedness := htmlElement(t, doc, "", "aria-labelledby", "affectedness-heading")
			rows := tableRecords(t, tableWithHeaders(t, affectedness, "Release", "Status"))
			require.Len(t, rows, 1)
			assert.Equal(t, "Fixed", rows[0]["Status"], "relevance must not imply affectedness")

			screening := htmlElement(t, doc, "", "aria-labelledby", "screening-heading")
			assert.Equal(t, tc.autoStatus, strings.TrimSpace(definition(t, screening, "Automated relevance").content()))
			assert.Contains(t, definition(t, screening, "Automated reason").content(), string(tc.reason))

			if tc.manual.Status != "" {
				assert.Regexp(
					t,
					"^"+strings.ReplaceAll(string(tc.manual.Status), "-", " ")+`\b`,
					strings.ToLower(definition(t, screening, "Manual relevance").content()),
				)
			} else {
				for _, term := range screening.all("dt") {
					assert.NotEqual(t, "Manual relevance", strings.TrimSpace(term.content()))
				}
			}

			if tc.manual.Justification != "" {
				assert.Contains(t, doc.content(), tc.manual.Justification)
			}
		})
	}
}

func TestCVE_PackageEvidencePreservesEscalationContext(t *testing.T) {
	t.Parallel()

	for _, basis := range []string{"no-authority", "eval-undecidable", "vendored-deferred"} {
		t.Run(basis, func(t *testing.T) {
			t.Parallel()

			pkg := assessment.PackageStatus{
				Reason: assessment.ReleaseReasonUnknownEscalated,
				Basis:  basis, BasisWhy: "Cannot assess <script>version</script>.",
				Vendored: basis == "vendored-deferred",
			}

			rec := relevantRecord("CVE-2024-0001", map[string]assessment.ReleaseDecision{
				"1877.26": autoDecision(map[string]assessment.PackageStatus{glID("glibc"): pkg}),
			})

			res := render(t, inventory(t, nil), []string{"1877.26"}, rec)

			content := readCVEPage(t, res.OutDir, rec.ID)

			doc := parseHTML(t, content)

			rows := tableRecords(t, tableWithHeaders(t, doc, "Source package", "Evidence basis"))
			require.Len(t, rows, 1)

			assert.Equal(t, "Unknown", rows[0]["Status"])
			assert.Contains(t, rows[0]["Reason"], "unknown-escalated")
			assert.Contains(t, rows[0]["Evidence basis"], basis)
			assert.Equal(t, pkg.BasisWhy, rows[0]["Explanation"])

			if pkg.Vendored {
				assert.NotEmpty(
					t,
					rows[0]["Vendored component"],
					"vendored evidence must remain identified without a component name",
				)
			} else {
				assert.Empty(t, rows[0]["Vendored component"])
			}

			assert.NotContains(t, content, "<script>version</script>")
		})
	}
}
