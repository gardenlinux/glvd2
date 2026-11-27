package presentation_test

import (
	"path/filepath"
	"regexp"
	"testing"

	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/gardenlinux/glvd2/internal/presentation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOverviewPage_ReleaseCountsIncludeUnknownAndOverlappingReview(t *testing.T) {
	t.Parallel()

	const version = "2000.1"
	inv := inventory(t, map[string]map[string][]string{version: {"metal": {"glibc"}}})

	reasons := []assessment.ReleaseStatusReason{
		assessment.ReleaseReasonVersionVulnerable,
		assessment.ReleaseReasonVersionFixed,
		assessment.ReleaseReasonDeclaredNotAffected,
		assessment.ReleaseReasonUnknownEscalated,
		assessment.ReleaseReasonAffectedEscalated,
	}

	recs := make([]assessment.Record, 0, len(reasons))
	for i, reason := range reasons {
		recs = append(recs, relevantRecord(idForSeq(i+1), map[string]assessment.ReleaseDecision{
			version: autoDecision(map[string]assessment.PackageStatus{glID("glibc"): autoPkg(reason)}),
		}))
	}

	res := render(t, inv, []string{version}, recs...)

	for _, page := range []string{"index.html", "releases/index.html"} {
		rows := pageTableRecords(t, res.OutDir, page, "Release", "Affected")
		require.Len(t, rows, 1)

		for field, want := range map[string]string{
			"Release": version, "Affected": "2", "Fixed": "1",
			"Not affected": "1", "Unknown": "1", "Needs review": "2", "Flavor analysis": "Available",
		} {
			assert.Equal(t, want, rows[0][field], "%s in %s", field, page)
		}
	}

	for _, page := range []string{releasePath(version), flavorPath(version, "metal")} {
		rows := pageTableRecords(t, res.OutDir, page, "CVE", "Needs review")

		var found bool

		for _, row := range rows {
			if row["CVE"] == idForSeq(4) {
				found = true
				assert.Equal(t, "Yes", row["Needs review"])
				assert.Contains(t, []string{row["Release status"], row["Flavor status"]}, "Unknown")
			}
		}

		assert.True(t, found, page)
	}
}

func TestOverviewPage_CountsEffectiveRelevance(t *testing.T) {
	t.Parallel()

	manual := relevantRecord("CVE-2024-0004", nil)
	manual.Manual.ManualTriage = assessment.ManualTriage{Status: assessment.StatusNotRelevant}

	res := render(t, inventory(t, nil), nil,
		relevantRecord("CVE-2024-0001", nil), notRelevantRecord("CVE-2024-0002", nil),
		undecidedRecord("CVE-2024-0003"), manual)

	doc := parseHTML(t, readFile(t, filepath.Join(res.OutDir, "index.html")))

	counts := htmlElement(t, doc, "", "aria-label", "CVE counts")

	for _, pattern := range []string{
		`\b4\s+CVE records`, `\b1\s+Relevant`, `\b2\s+Not relevant`, `\b1\s+Undecided`,
	} {
		assert.Regexp(t, pattern, counts.content())
	}
}

func TestOverviewPage_BuildRevision(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ name, sha, display string }{
		{"hash", "0123456789abcdef", "0123456"},
		{"short hash", "abcdef", "abcdef"},
		{"unknown", "", "unknown"},
		{"non hash", "development-build", "development-build"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s, err := presentation.NewRenderer(presentation.RenderConfig{OutDir: t.TempDir(), BuildSHA: tc.sha})
			require.NoError(t, err)

			res, err := s.Render(t.Context(), sliceSource(nil), inventory(t, nil), nil)
			require.NoError(t, err)

			doc := parseHTML(t, readFile(t, filepath.Join(res.OutDir, "index.html")))
			assert.Regexp(t, `\b`+regexp.QuoteMeta(tc.display)+`\b`, doc.content())
		})
	}
}
