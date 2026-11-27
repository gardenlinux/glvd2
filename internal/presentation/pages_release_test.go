package presentation_test

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type scopeResult struct {
	status, review string
	sources        []string
}

func assertScopeResults(t *testing.T, outDir, page, statusColumn string, want map[string]scopeResult) {
	t.Helper()

	doc := parseHTML(t, readFile(t, filepath.Join(outDir, page)))

	section := htmlElement(t, doc, "", "aria-labelledby", "cves-heading")

	if len(want) == 0 {
		for _, body := range section.all("tbody") {
			assert.Empty(t, body.all("tr"))
		}
		return
	}

	rows := tableRecords(t, tableWithHeaders(t, section, "CVE", statusColumn, "Needs review", "Source packages"))
	require.Len(t, rows, len(want))

	for _, row := range rows {
		expected, ok := want[row["CVE"]]

		require.True(t, ok, "unexpected CVE %s", row["CVE"])

		assert.Equal(t, expected.status, row[statusColumn])
		assert.Equal(t, expected.review, row["Needs review"])

		var sources []string

		for source := range strings.SplitSeq(row["Source packages"], ",") {
			if source = strings.TrimSpace(source); source != "" {
				sources = append(sources, source)
			}
		}

		assert.ElementsMatch(t, expected.sources, sources)
	}
}

func TestReleaseAndFlavorPages_ScopedDecisions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		auto    map[string]assessment.PackageStatus
		manual  map[string]assessment.PackageOverride
		members []string
		release scopeResult
		flavor  *scopeResult
	}{
		{
			name:    "source absent from flavor",
			members: []string{"glibc"},
			auto: map[string]assessment.PackageStatus{
				glID("aws-cli"): autoPkg(assessment.ReleaseReasonVersionVulnerable),
			},
			release: scopeResult{"Affected", "No", []string{glID("aws-cli")}},
		},
		{
			name:    "source included in flavor",
			members: []string{"glibc", "aws-cli"},
			auto: map[string]assessment.PackageStatus{
				glID("aws-cli"): autoPkg(assessment.ReleaseReasonVersionVulnerable),
			},
			release: scopeResult{"Affected", "No", []string{glID("aws-cli")}},
			flavor:  &scopeResult{"Affected", "No", []string{glID("aws-cli")}},
		},
		{
			name:    "manual override takes precedence",
			members: []string{"openssl"},
			auto: map[string]assessment.PackageStatus{
				glID("openssl"): autoPkg(assessment.ReleaseReasonVersionVulnerable),
			},
			manual: map[string]assessment.PackageOverride{
				glID("openssl"): override(assessment.ReleaseStatusNotAffected),
			},
			release: scopeResult{"Not affected", "No", []string{glID("openssl")}},
			flavor:  &scopeResult{"Not affected", "No", []string{glID("openssl")}},
		},
		{
			name:    "manual source absent from inventory",
			members: []string{"glibc"},
			manual: map[string]assessment.PackageOverride{
				glID("legacy-tool"): override(assessment.ReleaseStatusAffected),
			},
			release: scopeResult{"Affected", "No", []string{glID("legacy-tool")}},
		},
		{
			name:    "namespace tolerant membership",
			members: []string{"openssl"},
			auto: map[string]assessment.PackageStatus{
				debID("openssl"): autoPkg(assessment.ReleaseReasonVersionVulnerable),
			},
			release: scopeResult{"Affected", "No", []string{debID("openssl")}},
			flavor:  &scopeResult{"Affected", "No", []string{debID("openssl")}},
		},
		{
			name: "review reflects any package", members: []string{"glibc", "openssl"},
			auto: map[string]assessment.PackageStatus{
				glID("glibc"):   autoPkg(assessment.ReleaseReasonVersionVulnerable),
				glID("openssl"): autoPkg(assessment.ReleaseReasonAffectedEscalated),
			},
			release: scopeResult{"Affected", "Yes", []string{glID("glibc"), glID("openssl")}},
			flavor:  &scopeResult{"Affected", "Yes", []string{glID("glibc"), glID("openssl")}},
		},
		{
			name: "not shipped packages do not contribute", members: []string{"glibc", "openssl"},
			auto: map[string]assessment.PackageStatus{
				glID("glibc"):   autoPkg(assessment.ReleaseReasonVersionVulnerable),
				glID("openssl"): autoPkg(assessment.ReleaseReasonPackageNotShipped),
			},
			release: scopeResult{"Affected", "No", []string{glID("glibc")}},
			flavor:  &scopeResult{"Affected", "No", []string{glID("glibc")}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			inv := inventory(t, map[string]map[string][]string{"1877.26": {"kvm": tc.members}})

			rec := relevantRecord("CVE-2024-0001", map[string]assessment.ReleaseDecision{
				"1877.26": decision(tc.auto, tc.manual),
			})

			res := render(t, inv, []string{"1877.26"}, rec)
			assertScopeResults(
				t,
				res.OutDir,
				releasePath("1877.26"),
				"Release status",
				map[string]scopeResult{rec.ID: tc.release},
			)

			flavor := make(map[string]scopeResult)
			if tc.flavor != nil {
				flavor[rec.ID] = *tc.flavor
			} else {
				doc := parseHTML(t, readCVEPage(t, res.OutDir, rec.ID))
				rows := tableRecords(t, tableWithHeaders(t, doc, "Flavor", "Analysis coverage"))
				require.Len(t, rows, 1)
				assert.Equal(t, "Outside scope", rows[0]["Analysis coverage"])
			}

			assertScopeResults(t, res.OutDir, flavorPath("1877.26", "kvm"), "Flavor status", flavor)
		})
	}
}

func TestReleasePage_DistinguishesMissingAndEmptyResults(t *testing.T) {
	t.Parallel()

	inv := inventory(t, map[string]map[string][]string{"1877.26": {"kvm": {"glibc"}}})

	missing := relevantRecord("CVE-2024-0001", nil)

	empty := relevantRecord("CVE-2024-0002", map[string]assessment.ReleaseDecision{"1877.26": autoDecision(nil)})

	res := render(t, inv, []string{"1877.26"}, missing, empty)

	assertScopeResults(t, res.OutDir, releasePath("1877.26"), "Release status", map[string]scopeResult{
		empty.ID: {"Not affected", "No", nil},
	})

	assertScopeResults(t, res.OutDir, flavorPath("1877.26", "kvm"), "Flavor status", nil)

	missingPage := parseHTML(t, readCVEPage(t, res.OutDir, missing.ID))

	summary := htmlElement(t, missingPage, "", "aria-labelledby", "affectedness-heading")

	for _, body := range summary.all("tbody") {
		assert.Empty(t, body.all("tr"))
	}

	emptyPage := parseHTML(t, readCVEPage(t, res.OutDir, empty.ID))

	rows := tableRecords(t, tableWithHeaders(t, emptyPage, "Release", "Status"))
	require.Len(t, rows, 1)

	assert.Equal(t, "1877.26", rows[0]["Release"])
	assert.Equal(t, "Not affected", rows[0]["Status"])
}

func TestReleasePage_WithoutFlavorMembership(t *testing.T) {
	t.Parallel()

	rec := relevantRecord("CVE-2024-0001", map[string]assessment.ReleaseDecision{
		"1877.26": autoDecision(
			map[string]assessment.PackageStatus{glID("glibc"): autoPkg(assessment.ReleaseReasonVersionVulnerable)},
		),
	})

	res := render(t, inventory(t, nil), []string{"1877.26"}, rec)

	assertScopeResults(t, res.OutDir, releasePath("1877.26"), "Release status", map[string]scopeResult{
		rec.ID: {"Affected", "No", []string{glID("glibc")}},
	})

	assertFileNotExists(t, filepath.Join(res.OutDir, "releases", "1877.26", "flavors"))

	rows := pageTableRecords(t, res.OutDir, "index.html", "Release", "Flavor analysis")
	require.Len(t, rows, 1)

	assert.Equal(t, "Unavailable", rows[0]["Flavor analysis"])
}

func TestReleaseAndFlavorPages_ExcludeNonRelevantCVEs(t *testing.T) {
	t.Parallel()

	inv := inventory(t, map[string]map[string][]string{"1877.26": {"kvm": {"glibc"}}})

	decisions := map[string]assessment.ReleaseDecision{
		"1877.26": autoDecision(
			map[string]assessment.PackageStatus{glID("glibc"): autoPkg(assessment.ReleaseReasonVersionVulnerable)},
		),
	}

	relevant := relevantRecord("CVE-2024-0001", decisions)

	excluded := notRelevantRecord("CVE-2024-0002", decisions)

	undecided := assessment.Record{ID: "CVE-2024-0003", Releases: decisions}

	res := render(t, inv, []string{"1877.26"}, relevant, excluded, undecided)

	want := map[string]scopeResult{relevant.ID: {"Affected", "No", []string{glID("glibc")}}}

	assertScopeResults(t, res.OutDir, releasePath("1877.26"), "Release status", want)
	assertScopeResults(t, res.OutDir, flavorPath("1877.26", "kvm"), "Flavor status", want)

	assertFileExists(t, pageFor(res.OutDir, excluded.ID))
	assertFileExists(t, pageFor(res.OutDir, undecided.ID))
}

func TestReleasePage_ZeroFindingsRemainDiscoverable(t *testing.T) {
	t.Parallel()

	inv := inventory(t, map[string]map[string][]string{"1877.26": {"kvm": {"glibc"}}})

	res := render(t, inv, []string{"1877.26"})

	assertScopeResults(t, res.OutDir, releasePath("1877.26"), "Release status", nil)
	assertScopeResults(t, res.OutDir, flavorPath("1877.26", "kvm"), "Flavor status", nil)

	rows := pageTableRecords(t, res.OutDir, "index.html", "Release", "Affected")

	require.Len(t, rows, 1)

	assert.Equal(t, "1877.26", rows[0]["Release"])
	assert.Equal(t, "0", rows[0]["Affected"])
}

func TestReleaseAndFlavorPages_ScopeFilterOptions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name              string
		reasons           []assessment.ReleaseStatusReason
		statuses, reviews []string
	}{
		{
			"both groups",
			[]assessment.ReleaseStatusReason{
				assessment.ReleaseReasonVersionVulnerable,
				assessment.ReleaseReasonAffectedEscalated,
				assessment.ReleaseReasonDeclaredNotAffected,
			},
			[]string{"", "affected", "not-affected"},
			[]string{"", "yes", "no"},
		},
		{
			"status only",
			[]assessment.ReleaseStatusReason{
				assessment.ReleaseReasonVersionVulnerable,
				assessment.ReleaseReasonVersionFixed,
			},
			[]string{"", "affected", "fixed"},
			nil,
		},
		{
			"review only",
			[]assessment.ReleaseStatusReason{
				assessment.ReleaseReasonVersionVulnerable,
				assessment.ReleaseReasonAffectedEscalated,
			},
			nil,
			[]string{"", "yes", "no"},
		},
		{"no distinct values", []assessment.ReleaseStatusReason{assessment.ReleaseReasonVersionVulnerable}, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			inv := inventory(t, map[string]map[string][]string{"1877.26": {"kvm": {"glibc"}}})

			var recs []assessment.Record

			for i, reason := range tc.reasons {
				recs = append(recs, relevantRecord(idForSeq(i+1), map[string]assessment.ReleaseDecision{
					"1877.26": autoDecision(map[string]assessment.PackageStatus{glID("glibc"): autoPkg(reason)}),
				}))
			}

			res := render(t, inv, []string{"1877.26"}, recs...)

			for _, page := range []string{releasePath("1877.26"), flavorPath("1877.26", "kvm")} {
				doc := parseHTML(t, readFile(t, filepath.Join(res.OutDir, page)))

				table := tableWithHeaders(t, doc, "CVE", "Needs review")
				assert.Len(t, tableRecords(t, table), len(recs))

				if tc.statuses == nil && tc.reviews == nil {
					assert.Empty(t, table.attrs["data-scope-filter"])
					continue
				}

				require.NotEmpty(t, table.attrs["data-scope-filter"])

				panel := htmlElement(t, doc, "", "id", table.attrs["data-scope-filter"])

				heads := table.all("thead")
				require.Len(t, heads, 1)

				groups := 0
				for column, header := range heads[0].all("th") {
					var tokens []string

					switch strings.TrimSpace(header.content()) {
					case "Release status", "Flavor status":
						tokens = tc.statuses
					case "Needs review":
						tokens = tc.reviews
					}

					if tokens == nil {
						continue
					}

					groups++
					group := htmlElement(t, panel, "", "data-filter-column", strconv.Itoa(column))

					var got []string
					for _, button := range group.all("button") {
						token := button.attrs["data-filter-value"]
						got = append(got, token)
						if token != "" {
							htmlElement(t, table, "td", "data-search", token)
						}
					}

					assert.ElementsMatch(t, tokens, got)
				}
				var actualGroups int

				for _, node := range panel.all("") {
					if _, ok := node.attrs["data-filter-column"]; ok {
						actualGroups++
					}
				}

				assert.Equal(t, groups, actualGroups)
			}
		})
	}
}
