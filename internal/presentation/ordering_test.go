package presentation_test

import (
	"path/filepath"
	"regexp"
	"testing"

	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/stretchr/testify/assert"
)

func TestPages_OrderReleasesNumericallyAndCVEsNewestFirst(t *testing.T) {
	t.Parallel()

	inv := inventory(t, map[string]map[string][]string{
		"1877.26": {
			"metal": {"glibc"},
			"aws":   {"glibc"},
		},
	})

	releases := map[string]assessment.ReleaseDecision{
		"184.0": autoDecision(nil), "1877.9": autoDecision(nil),
		"1877.10": autoDecision(nil), "nightly": autoDecision(nil),
		"1877.26": autoDecision(map[string]assessment.PackageStatus{
			glID("glibc"): autoPkg(assessment.ReleaseReasonVersionVulnerable),
		}),
	}

	recs := []assessment.Record{
		relevantRecord("CVE-2024-9999", releases),
		relevantRecord("CVE-2023-10000", releases),
		relevantRecord("CVE-2024-10000", releases),
	}

	res := render(t, inv,
		[]string{"nightly", "1877.26", "1877.10", "1877.9", "184.0"}, recs...)

	rows := pageTableRecords(t, res.OutDir, "index.html", "Release")

	assert.Equal(t, []string{"1877.26", "1877.10", "1877.9", "184.0", "nightly"}, recordValues(rows, "Release"))

	for _, page := range []string{releasePath("1877.26"), flavorPath("1877.26", "aws"), packagePath("glibc")} {
		rows = pageTableRecords(t, res.OutDir, page, "CVE")
		assert.Equal(t, []string{"CVE-2024-10000", "CVE-2024-9999", "CVE-2023-10000"}, recordValues(rows, "CVE"), page)
	}

	doc := parseHTML(t, readFile(t, filepath.Join(res.OutDir, releasePath("1877.26"))))

	section := htmlElement(t, doc, "", "aria-labelledby", "flavors-heading")
	links := section.all("a")
	flavors := make([]string, 0, len(links))
	for _, link := range links {
		flavors = append(flavors, link.content())
	}

	assert.Equal(t, []string{"aws", "metal"}, flavors)
}

func TestCVEListing_OrdersNewestFirst(t *testing.T) {
	t.Parallel()

	recs := []assessment.Record{
		undecidedRecord("CVE-2024-0100"),
		undecidedRecord("CVE-2026-9999"),
		undecidedRecord("CVE-2025-0050"),
		undecidedRecord("CVE-2026-10000"),
	}

	res := render(t, inventory(t, nil), nil, recs...)

	rows := pageTableRecords(t, res.OutDir, "cves/undecided/index.html", "CVE")
	assert.Equal(
		t,
		[]string{"CVE-2026-10000", "CVE-2026-9999", "CVE-2025-0050", "CVE-2024-0100"},
		recordValues(rows, "CVE"),
	)
}

func TestRenderer_TraversalOrderIndependence(t *testing.T) {
	t.Parallel()

	inv := inventory(t, map[string]map[string][]string{
		"1877.26": {"kvm": {"glibc"}},
	})

	recs := buildCVEs(5, map[string]assessment.ReleaseDecision{
		"1877.26": autoDecision(map[string]assessment.PackageStatus{
			glID("glibc"): autoPkg(assessment.ReleaseReasonVersionVulnerable),
		}),
	})

	reversed := make([]assessment.Record, len(recs))
	for i, rec := range recs {
		reversed[len(recs)-1-i] = rec
	}

	forward := render(t, inv, []string{"1877.26"}, recs...)
	backward := render(t, inv, []string{"1877.26"}, reversed...)

	first, second := collectTree(t, forward.OutDir), collectTree(t, backward.OutDir)

	generated := regexp.MustCompile(`\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC`)
	for _, tree := range []map[string]string{first, second} {
		for _, path := range []string{"index.html", "assets/footer-meta.js"} {
			tree[path] = generated.ReplaceAllString(tree[path], "<timestamp>")
		}
	}

	assert.Equal(t, first, second, "traversal order must not affect generated content")
}
