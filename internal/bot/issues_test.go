package bot_test

import (
	"strings"
	"testing"

	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/gardenlinux/glvd2/internal/bot"
	"github.com/stretchr/testify/assert"
)

func TestIssueTitle_MultibyteDescription(t *testing.T) {
	t.Parallel()
	desc := strings.Repeat("é", 40) + ". trailing text that should be dropped"
	rec := &assessment.Record{
		ID:       "CVE-2024-1234",
		Upstream: assessment.UpstreamData{Description: desc},
	}

	title := bot.IssueTitle(rec)
	assert.Equal(t, "CVE-2024-1234: "+strings.Repeat("é", 40)+".", title)
}

func TestIssueTitle_LongDescriptionNoPeriod(t *testing.T) {
	t.Parallel()
	desc := strings.Repeat("a", 100)
	rec := &assessment.Record{
		ID:       "CVE-2024-1234",
		Upstream: assessment.UpstreamData{Description: desc},
	}

	title := bot.IssueTitle(rec)
	assert.Equal(t, "CVE-2024-1234: "+strings.Repeat("a", 80)+"…", title)
}

func TestIssueTitle_NoDescription(t *testing.T) {
	t.Parallel()
	rec := &assessment.Record{ID: "CVE-2024-1234"}
	assert.Equal(t, "CVE-2024-1234", bot.IssueTitle(rec))
}

func TestIssueTitle_ShortDescription(t *testing.T) {
	t.Parallel()
	rec := &assessment.Record{
		ID:       "CVE-2024-1234",
		Upstream: assessment.UpstreamData{Description: "Short one."},
	}
	assert.Equal(t, "CVE-2024-1234: Short one.", bot.IssueTitle(rec))
}
