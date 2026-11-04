package bot

import (
	"strings"
	"testing"

	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/stretchr/testify/assert"
)

func TestIssueTitle_MultibyteDescription(t *testing.T) {
	// A description with multibyte UTF-8 before the first period must not panic:
	// the first-sentence cut works on rune indices, not byte indices.
	desc := strings.Repeat("é", 40) + ". trailing text that should be dropped"
	rec := &assessment.Record{
		ID:       "CVE-2024-1234",
		Upstream: assessment.UpstreamData{Description: desc},
	}

	title := issueTitle(rec)
	assert.Equal(t, "CVE-2024-1234: "+strings.Repeat("é", 40)+".", title)
}

func TestIssueTitle_LongDescriptionNoPeriod(t *testing.T) {
	// No period within the cap: truncate to 80 runes and append an ellipsis.
	desc := strings.Repeat("a", 100)
	rec := &assessment.Record{
		ID:       "CVE-2024-1234",
		Upstream: assessment.UpstreamData{Description: desc},
	}

	title := issueTitle(rec)
	assert.Equal(t, "CVE-2024-1234: "+strings.Repeat("a", 80)+"…", title)
}

func TestIssueTitle_NoDescription(t *testing.T) {
	rec := &assessment.Record{ID: "CVE-2024-1234"}
	assert.Equal(t, "CVE-2024-1234", issueTitle(rec))
}

func TestIssueTitle_ShortDescription(t *testing.T) {
	rec := &assessment.Record{
		ID:       "CVE-2024-1234",
		Upstream: assessment.UpstreamData{Description: "Short one."},
	}
	assert.Equal(t, "CVE-2024-1234: Short one.", issueTitle(rec))
}
