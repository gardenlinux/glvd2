package presentation_test

import (
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCVELanding_SearchAndEmptyUndecidedListingRemainAvailable(t *testing.T) {
	t.Parallel()

	rec := notRelevantRecord("CVE-2025-9999", nil)

	res := render(t, inventory(t, nil), nil, rec)

	landing := parseHTML(t, readFile(t, filepath.Join(res.OutDir, "cves", "index.html")))

	form := htmlElement(t, landing, "form", "class", "cve-search")

	htmlElement(t, form, "input", "id", "cve-id")
	htmlElement(t, landing, "script", "src", "../assets/search.js")

	assertFileExists(t, pageFor(res.OutDir, rec.ID))
	assertFileNotExists(t, filepath.Join(res.OutDir, "cves", "relevant"))
	assertFileNotExists(t, filepath.Join(res.OutDir, "cves", "not-relevant"))

	undecided := parseHTML(t, readFile(t, filepath.Join(res.OutDir, "cves", "undecided", "index.html")))
	for _, body := range undecided.all("tbody") {
		assert.Empty(t, body.all("tr"))
	}

	htmlElement(t, undecided, "a", "href", "../index.html")
}

func TestCVEListing_OnlyUndecidedRecordsWithTrackingAndPublicationDates(t *testing.T) {
	t.Parallel()

	rec := undecidedRecord("CVE-2024-0003")
	rec.Upstream.PublishedAt = time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)
	rec.Meta.FirstSeenAt = time.Date(2024, 5, 2, 8, 30, 0, 0, time.UTC)

	res := render(t, inventory(t, nil), nil, rec,
		relevantRecord("CVE-2024-0001", nil), notRelevantRecord("CVE-2024-0002", nil))

	rows := pageTableRecords(t, res.OutDir, "cves/undecided/index.html", "CVE", "Undecided since")
	require.Len(t, rows, 1)

	for field, want := range map[string]string{"CVE": rec.ID, "Undecided since": "2024-05-02", "Published": "2024-03-01"} {
		assert.Equal(t, want, rows[0][field], field)
	}

	doc := parseHTML(t, readCVEPage(t, res.OutDir, rec.ID))

	tracked := definition(t, doc, "First tracked by GLVD")

	htmlElement(t, tracked, "time", "datetime", "2024-05-02")
}

func TestListings_IncludeAllRecords(t *testing.T) {
	t.Parallel()

	inv := inventory(t, map[string]map[string][]string{"1877.26": {"kvm": {"glibc"}}})

	const count = 125
	recs := buildCVEs(count, map[string]assessment.ReleaseDecision{
		"1877.26": autoDecision(map[string]assessment.PackageStatus{
			glID("glibc"): autoPkg(assessment.ReleaseReasonVersionVulnerable),
		}),
	})
	relevantIDs := make([]string, 0, len(recs))
	undecidedIDs := make([]string, 0, count)

	for _, rec := range recs {
		relevantIDs = append(relevantIDs, rec.ID)
	}

	for i := range count {
		rec := undecidedRecord("CVE-2025-" + strconv.Itoa(1000+i))
		recs = append(recs, rec)
		undecidedIDs = append(undecidedIDs, rec.ID)
	}

	res := render(t, inv, []string{"1877.26"}, recs...)

	for _, page := range []string{releasePath("1877.26"), flavorPath("1877.26", "kvm"), packagePath("glibc")} {
		rows := pageTableRecords(t, res.OutDir, page, "CVE")
		assert.ElementsMatch(t, relevantIDs, recordValues(rows, "CVE"), page)
	}

	rows := pageTableRecords(t, res.OutDir, "cves/undecided/index.html", "CVE")

	assert.ElementsMatch(t, undecidedIDs, recordValues(rows, "CVE"))
}
