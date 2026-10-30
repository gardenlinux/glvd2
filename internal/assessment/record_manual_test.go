package assessment_test

import (
	"testing"
	"time"

	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManualTriage_HistoryPreservesAll(t *testing.T) {
	mt := assessment.ManualTriage{}

	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := t1.Add(time.Hour)

	mt.History = append(mt.History, assessment.ManualTriageEntry{
		Status: assessment.StatusRelevant, Author: "alice", At: t1, IssueComment: 1,
	})
	mt.History = append(mt.History, assessment.ManualTriageEntry{
		Status: assessment.StatusNotRelevant, Author: "bob", At: t2, IssueComment: 2,
	})

	require.Len(t, mt.History, 2)
	assert.Equal(t, assessment.StatusRelevant, mt.History[0].Status)
	assert.Equal(t, "alice", mt.History[0].Author)
	assert.Equal(t, assessment.StatusNotRelevant, mt.History[1].Status)
	assert.Equal(t, "bob", mt.History[1].Author)
}

func TestPackageOverride_ScoreOverride(t *testing.T) {
	score := 3.1
	po := assessment.PackageOverride{
		Status:        assessment.ReleaseStatusNotAffected,
		Justification: "mitigated",
		ScoreOverride: &score,
	}

	assert.False(t, po.IsEmpty())
	require.NotNil(t, po.ScoreOverride)
	assert.InDelta(t, 3.1, *po.ScoreOverride, 0.001)
}

func TestPackageOverride_IsEmpty_WithScore(t *testing.T) {
	assert.True(t, assessment.PackageOverride{}.IsEmpty())
	assert.False(t, assessment.PackageOverride{Status: assessment.ReleaseStatusAffected}.IsEmpty())
}

func TestPackageOverride_HistoryPreservesScoreOverride(t *testing.T) {
	score1 := 4.0
	score2 := 2.5
	po := assessment.PackageOverride{}

	po.History = append(po.History, assessment.PackageOverrideEntry{
		ScoreOverride: &score1, Author: "alice", IssueComment: 10,
	})
	po.History = append(po.History, assessment.PackageOverrideEntry{
		ScoreOverride: &score2, Author: "bob", IssueComment: 11,
	})

	require.Len(t, po.History, 2)
	assert.InDelta(t, 4.0, *po.History[0].ScoreOverride, 0.001)
	assert.InDelta(t, 2.5, *po.History[1].ScoreOverride, 0.001)
}
