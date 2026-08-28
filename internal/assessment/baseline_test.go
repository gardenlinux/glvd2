package assessment_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/gardenlinux/glvd2/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeGitReader returns predefined responses.
type fakeGitReader struct {
	commitSHA string
	commitErr error

	diffFiles []string
	diffErr   error

	// showFiles maps "commit:path" to content. nil content means file not found.
	showFiles map[string][]byte
	showErr   error
}

func (f *fakeGitReader) FindCommitByMessageAnchor(_ context.Context, _ string) (string, error) {
	return f.commitSHA, f.commitErr
}

func (f *fakeGitReader) DiffFilesSince(_ context.Context, _, _ string) ([]string, error) {
	return f.diffFiles, f.diffErr
}

func (f *fakeGitReader) ShowFileAtCommit(_ context.Context, commitSHA, filePath string) ([]byte, error) {
	if f.showErr != nil {
		return nil, f.showErr
	}
	key := commitSHA + ":" + filePath
	content, ok := f.showFiles[key]
	if !ok {
		return nil, nil
	}
	return content, nil
}

func testConfig() *config.AppConfig {
	return &config.AppConfig{
		AssessmentsDir:       "data/assessments",
		BaselineCommitAnchor: "GLVD2-Baseline: true",
	}
}

func TestBaseline_FirstRun(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	gitReader := &fakeGitReader{commitSHA: ""}

	b, err := assessment.NewBaseline(ctx, gitReader, testConfig())
	require.NoError(t, err)

	assert.True(t, b.IsFirstRun())
	assert.Empty(t, b.CommitSHA())

	files, err := b.ExternallyModifiedFiles(ctx)
	require.NoError(t, err)
	assert.Nil(t, files)

	rec, err := b.LoadAssessmentRecord(ctx, "CVE-2025-1234")
	require.NoError(t, err)
	assert.Equal(t, assessment.Record{}, rec)
}

func TestBaseline_FindsProgramCommit(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	gitReader := &fakeGitReader{commitSHA: "abc123def456"}

	b, err := assessment.NewBaseline(ctx, gitReader, testConfig())
	require.NoError(t, err)

	assert.False(t, b.IsFirstRun())
	assert.Equal(t, "abc123def456", b.CommitSHA())
}

func TestBaseline_LoadAssessmentRecord(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	rec := assessment.Record{
		ID: "CVE-2025-2000",
		Upstream: assessment.UpstreamData{
			Description: "original description",
		},
		Screening: assessment.ScreeningResult{
			AutoTriage: assessment.Triage{Status: assessment.StatusRelevant, Justification: "reason"},
		},
	}

	data, err := json.Marshal(rec)
	require.NoError(t, err)

	gitReader := &fakeGitReader{
		commitSHA: "abc123",
		showFiles: map[string][]byte{
			"abc123:data/assessments/2025/2xxx/CVE-2025-2000.json": data,
		},
	}

	b, err := assessment.NewBaseline(ctx, gitReader, testConfig())
	require.NoError(t, err)

	loaded, err := b.LoadAssessmentRecord(ctx, "CVE-2025-2000")
	require.NoError(t, err)

	assert.Equal(t, rec, loaded)
}

func TestBaseline_LoadAssessmentRecord_NotFound(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	gitReader := &fakeGitReader{
		commitSHA: "abc123",
		showFiles: map[string][]byte{}, // no files
	}

	b, err := assessment.NewBaseline(ctx, gitReader, testConfig())
	require.NoError(t, err)

	loaded, err := b.LoadAssessmentRecord(ctx, "CVE-2025-9999")
	require.NoError(t, err)
	assert.Equal(t, assessment.Record{}, loaded)
}

func TestBaseline_ExternallyModifiedFiles(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	gitReader := &fakeGitReader{
		commitSHA: "abc123",
		diffFiles: []string{"data/assessments/2025/3xxx/CVE-2025-3000.json"},
	}

	b, err := assessment.NewBaseline(ctx, gitReader, testConfig())
	require.NoError(t, err)

	files, err := b.ExternallyModifiedFiles(ctx)
	require.NoError(t, err)

	assert.Len(t, files, 1)
	assert.Contains(t, files[0], "CVE-2025-3000.json")
}

func TestBaseline_ExternallyModifiedFiles_Empty(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	gitReader := &fakeGitReader{
		commitSHA: "abc123",
		diffFiles: nil,
	}

	b, err := assessment.NewBaseline(ctx, gitReader, testConfig())
	require.NoError(t, err)

	files, err := b.ExternallyModifiedFiles(ctx)
	require.NoError(t, err)

	assert.Nil(t, files)
}
