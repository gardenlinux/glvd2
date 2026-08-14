package assessment_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/gardenlinux/glvd2/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStore_RoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := assessment.NewStore(&config.AppConfig{AssessmentDataDir: dir})

	rec := assessment.Record{
		ID: "CVE-2025-4176",
		Upstream: assessment.UpstreamData{
			Description: "A test vulnerability in foo package.",
		},
		Screening: assessment.ScreeningResult{
			AutoTriage: assessment.Triage{Status: assessment.StatusRelevant, Justification: "affects foo"},
		},
		Releases: map[string]assessment.ReleaseDecision{
			"2150.8.0": {
				AutoTriage: assessment.ReleaseTriage{
					Status: assessment.ImpactAffected, Justification: "ships foo 1.0",
				},
			},
		},
	}

	err := store.Save(rec)
	require.NoError(t, err)

	got, err := store.Get("CVE-2025-4176")
	require.NoError(t, err)
	assert.Equal(t, rec, got)
}

func TestStore_GetNotFound(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := assessment.NewStore(&config.AppConfig{AssessmentDataDir: dir})

	_, err := store.Get("CVE-2025-9999")
	require.Error(t, err)
	assert.ErrorIs(t, err, assessment.ErrRecordNotFound)
}

func TestStore_Save_CreatesDirectories(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := assessment.NewStore(&config.AppConfig{AssessmentDataDir: dir})

	rec := assessment.Record{
		ID: "CVE-2024-50001",
		Upstream: assessment.UpstreamData{
			Description: "High-numbered CVE in the 50xxx bucket.",
		},
	}

	err := store.Save(rec)
	require.NoError(t, err)

	// Verify the intermediate directories were created with the expected bucketing scheme.
	bucketDir := filepath.Join(dir, "2024", "50xxx")
	info, statErr := os.Stat(bucketDir)
	require.NoError(t, statErr, "bucket directory %q should exist", bucketDir)
	assert.True(t, info.IsDir(), "%q should be a directory", bucketDir)
}

func TestStore_Save_Overwrites(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := assessment.NewStore(&config.AppConfig{AssessmentDataDir: dir})

	rec := assessment.Record{
		ID: "CVE-2025-1000",
		Upstream: assessment.UpstreamData{
			Description: "Original description.",
		},
	}

	require.NoError(t, store.Save(rec))

	rec.Upstream.Description = "Updated description."
	require.NoError(t, store.Save(rec))

	got, err := store.Get("CVE-2025-1000")
	require.NoError(t, err)
	assert.Equal(t, "Updated description.", got.Upstream.Description)
}

func TestStore_Get_InvalidID(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := assessment.NewStore(&config.AppConfig{AssessmentDataDir: dir})

	_, err := store.Get("not-a-cve")
	require.Error(t, err)
	assert.NotErrorIs(t, err, assessment.ErrRecordNotFound)
}

func TestStore_Save_InvalidID(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := assessment.NewStore(&config.AppConfig{AssessmentDataDir: dir})

	rec := assessment.Record{ID: "not-a-cve"}
	err := store.Save(rec)
	require.Error(t, err)
}
