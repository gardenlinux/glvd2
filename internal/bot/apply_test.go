package bot

import (
	"testing"
	"time"

	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var fixedTime = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

var testCtx = CommandContext{
	Actor:        "alice",
	IssueComment: 99,
	Now:          fixedTime,
}

func emptyRecord() *assessment.Record {
	return &assessment.Record{ID: "CVE-2024-1234"}
}

func TestApplyCommands_Relevant(t *testing.T) {
	rec := emptyRecord()
	_, err := ApplyCommands(rec, "/relevant confirmed reachable", testCtx)
	require.NoError(t, err)

	assert.Equal(t, assessment.StatusRelevant, rec.Manual.ManualTriage.Status)
	assert.Equal(t, "confirmed reachable", rec.Manual.ManualTriage.Justification)
	require.Len(t, rec.Manual.ManualTriage.History, 1)
	h := rec.Manual.ManualTriage.History[0]
	assert.Equal(t, assessment.StatusRelevant, h.Status)
	assert.Equal(t, "confirmed reachable", h.Justification)
	assert.Equal(t, "alice", h.Author)
	assert.Equal(t, fixedTime, h.At)
	assert.Equal(t, int64(99), h.IssueComment)
}

func TestApplyCommands_NotRelevant(t *testing.T) {
	rec := emptyRecord()
	_, err := ApplyCommands(rec, "/not-relevant false positive", testCtx)
	require.NoError(t, err)

	assert.Equal(t, assessment.StatusNotRelevant, rec.Manual.ManualTriage.Status)
	assert.Equal(t, "false positive", rec.Manual.ManualTriage.Justification)
	require.Len(t, rec.Manual.ManualTriage.History, 1)
}

func TestApplyCommands_RelevantThenNotRelevant_KeepsHistory(t *testing.T) {
	rec := emptyRecord()
	_, err := ApplyCommands(rec, "/relevant first decision", testCtx)
	require.NoError(t, err)

	ctx2 := CommandContext{Actor: "bob", IssueComment: 100, Now: fixedTime.Add(time.Hour)}
	_, err = ApplyCommands(rec, "/not-relevant changed my mind", ctx2)
	require.NoError(t, err)

	assert.Equal(t, assessment.StatusNotRelevant, rec.Manual.ManualTriage.Status)
	assert.Len(t, rec.Manual.ManualTriage.History, 2)
	assert.Equal(t, assessment.StatusRelevant, rec.Manual.ManualTriage.History[0].Status)
	assert.Equal(t, assessment.StatusNotRelevant, rec.Manual.ManualTriage.History[1].Status)
	assert.Equal(t, "bob", rec.Manual.ManualTriage.History[1].Author)
}

func TestApplyCommands_Notes(t *testing.T) {
	rec := emptyRecord()
	_, err := ApplyCommands(rec, "/notes see also CVE-2018-3646", testCtx)
	require.NoError(t, err)
	assert.Equal(t, "see also CVE-2018-3646", rec.Manual.Notes)
}

func TestApplyCommands_Override_CreatesReleaseBlock(t *testing.T) {
	rec := emptyRecord()
	_, err := ApplyCommands(rec, "/override release=1592.15 pkg=linux status=not-affected subsystem not compiled", testCtx)
	require.NoError(t, err)

	purl := "pkg:deb/debian/linux"
	rd, ok := rec.Releases["1592.15"]
	require.True(t, ok, "release block should be created")
	pkg, ok := rd.Manual.Packages[purl]
	require.True(t, ok, "package entry should be created")
	assert.Equal(t, assessment.ReleaseStatusNotAffected, pkg.Status)
	assert.Equal(t, "subsystem not compiled", pkg.Justification)
	require.Len(t, pkg.History, 1)
	assert.Equal(t, "alice", pkg.History[0].Author)
	assert.Equal(t, int64(99), pkg.History[0].IssueComment)
}

func TestApplyCommands_Override_UsesAutoKeyForShortName(t *testing.T) {
	rec := emptyRecord()
	rec.Releases = map[string]assessment.ReleaseDecision{
		"1592.15": {
			Auto: assessment.AutoReleaseStatus{
				Packages: map[string]assessment.PackageStatus{
					"pkg:deb/debian/linux": {},
				},
			},
		},
	}

	_, err := ApplyCommands(rec, "/override release=1592.15 pkg=linux status=fixed", testCtx)
	require.NoError(t, err)

	_, ok := rec.Releases["1592.15"].Manual.Packages["pkg:deb/debian/linux"]
	assert.True(t, ok, "should resolve short name via auto data")
}

func TestApplyCommands_Override_AppendHistory(t *testing.T) {
	rec := emptyRecord()
	_, err := ApplyCommands(rec, "/override release=1592.15 pkg=linux status=not-affected first", testCtx)
	require.NoError(t, err)

	ctx2 := CommandContext{Actor: "bob", IssueComment: 200, Now: fixedTime.Add(time.Hour)}
	_, err = ApplyCommands(rec, "/override release=1592.15 pkg=linux status=affected updated", ctx2)
	require.NoError(t, err)

	pkg := rec.Releases["1592.15"].Manual.Packages["pkg:deb/debian/linux"]
	assert.Equal(t, assessment.ReleaseStatusAffected, pkg.Status)
	assert.Len(t, pkg.History, 2)
	assert.Equal(t, assessment.ReleaseStatusNotAffected, pkg.History[0].Status)
	assert.Equal(t, assessment.ReleaseStatusAffected, pkg.History[1].Status)
}

func TestApplyCommands_Rescore(t *testing.T) {
	rec := emptyRecord()
	_, err := ApplyCommands(rec, "/rescore release=1592.15 pkg=linux score=3.1 mitigated", testCtx)
	require.NoError(t, err)

	pkg := rec.Releases["1592.15"].Manual.Packages["pkg:deb/debian/linux"]
	require.NotNil(t, pkg.ScoreOverride)
	assert.InDelta(t, 3.1, *pkg.ScoreOverride, 0.001)
	assert.Equal(t, "mitigated", pkg.Justification)
	require.Len(t, pkg.History, 1)
	require.NotNil(t, pkg.History[0].ScoreOverride)
	assert.InDelta(t, 3.1, *pkg.History[0].ScoreOverride, 0.001)
}

func TestApplyCommands_Rescore_InvalidScore(t *testing.T) {
	rec := emptyRecord()
	_, err := ApplyCommands(rec, "/rescore release=1592.15 pkg=linux score=11.0", testCtx)
	assert.Error(t, err)
}

func TestApplyCommands_Rescore_FullPURL(t *testing.T) {
	rec := emptyRecord()
	_, err := ApplyCommands(rec, "/rescore release=1592.15 pkg=pkg:deb/debian/openssl score=5.0", testCtx)
	require.NoError(t, err)

	_, ok := rec.Releases["1592.15"].Manual.Packages["pkg:deb/debian/openssl"]
	assert.True(t, ok, "full PURL should be used as-is")
}

func TestApplyCommands_ReopenSkipped(t *testing.T) {
	rec := emptyRecord()
	// /reopen should not touch the record
	_, err := ApplyCommands(rec, "/reopen needs more work", testCtx)
	require.NoError(t, err)
	assert.Equal(t, assessment.StatusUndecided, rec.Manual.ManualTriage.Status)
}

func TestApplyCommands_ParseError(t *testing.T) {
	rec := emptyRecord()
	parseErrs, applyErr := ApplyCommands(rec, "/rescore release=1592.15 pkg=linux score=bad", testCtx)
	assert.Nil(t, applyErr)
	assert.Len(t, parseErrs, 1)
}

func TestApplyCommands_MultipleCommands(t *testing.T) {
	rec := emptyRecord()
	body := "/relevant confirmed\n/notes see also related CVE"
	_, err := ApplyCommands(rec, body, testCtx)
	require.NoError(t, err)

	assert.Equal(t, assessment.StatusRelevant, rec.Manual.ManualTriage.Status)
	assert.Equal(t, "see also related CVE", rec.Manual.Notes)
}
