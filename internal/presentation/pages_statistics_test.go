package presentation_test

import (
	"path/filepath"
	"testing"

	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStatisticsPage_CountsAutomatedReasonsDespiteManualOverride(t *testing.T) {
	t.Parallel()

	relevant := relevantRecord("CVE-2024-0001", nil)

	notRelevant := notRelevantRecord("CVE-2024-0002", nil)
	notRelevant.Upstream.State = assessment.CVEStateRejected

	undecided := undecidedRecord("CVE-2024-0003")

	manual := relevantRecord("CVE-2024-0004", nil)
	manual.Manual.ManualTriage = assessment.ManualTriage{Status: assessment.StatusNotRelevant, Justification: "n/a"}
	manual.Upstream.State = assessment.CVEStatePublished

	res := render(t, inventory(t, nil), nil, relevant, notRelevant, undecided, manual)

	doc := parseHTML(t, readFile(t, filepath.Join(res.OutDir, "statistics", "index.html")))

	manualSection := htmlElement(t, doc, "", "aria-labelledby", "manual-heading")

	assert.Regexp(t, `\b1\b`, manualSection.content())

	for _, tc := range []struct {
		column string
		counts map[string]string
	}{
		{"Reason", map[string]string{"Affects debian package": "2", "Rejected upstream": "1", "Awaiting debian": "1"}},
		{"State", map[string]string{"Published": "1", "Rejected": "1"}},
	} {
		rows := tableRecords(t, tableWithHeaders(t, doc, tc.column, "CVEs"))
		require.Len(t, rows, len(tc.counts))

		actual := make(map[string]string)

		for _, row := range rows {
			actual[row[tc.column]] = row["CVEs"]
		}

		assert.Equal(t, tc.counts, actual)
	}
}
