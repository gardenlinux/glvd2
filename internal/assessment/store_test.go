package assessment_test

import (
	"context"
	"errors"
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
	store := assessment.NewStore(&config.AppConfig{AssessmentsDir: dir})

	rec := assessment.Record{
		ID: "CVE-2025-4176",
		Upstream: assessment.UpstreamData{
			Description: "A test vulnerability in foo package.",
		},
		Screening: assessment.ScreeningResult{
			AutoTriage: assessment.AutoTriage{Reason: assessment.TriageReasonAffectsDebianPackage},
		},
		Releases: map[string]assessment.ReleaseDecision{
			"2150.8.0": {
				Auto: assessment.AutoReleaseStatus{Packages: map[string]assessment.PackageStatus{
					"pkg:deb/debian/foo": {
						Reason:         assessment.ReleaseReasonVersionVulnerable,
						ShippedVersion: "1.0-1",
					},
				}},
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
	store := assessment.NewStore(&config.AppConfig{AssessmentsDir: dir})

	_, err := store.Get("CVE-2025-9999")
	require.Error(t, err)
	assert.ErrorIs(t, err, assessment.ErrRecordNotFound)
}

func TestStore_Save_CreatesDirectories(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := assessment.NewStore(&config.AppConfig{AssessmentsDir: dir})

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
	store := assessment.NewStore(&config.AppConfig{AssessmentsDir: dir})

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
	store := assessment.NewStore(&config.AppConfig{AssessmentsDir: dir})

	_, err := store.Get("not-a-cve")
	require.Error(t, err)
	assert.NotErrorIs(t, err, assessment.ErrRecordNotFound)
}

func TestStore_Save_InvalidID(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := assessment.NewStore(&config.AppConfig{AssessmentsDir: dir})

	rec := assessment.Record{ID: "not-a-cve"}
	err := store.Save(rec)
	require.Error(t, err)
}

func TestStore_Walk_VisitsAllRecords(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := assessment.NewStore(&config.AppConfig{AssessmentsDir: dir})

	ids := []string{"CVE-2024-0001", "CVE-2024-50001", "CVE-2023-9"}
	for _, id := range ids {
		require.NoError(t, store.Save(assessment.Record{ID: id}))
	}

	seen := make(map[string]struct{})
	err := store.Walk(t.Context(), func(rec assessment.Record) error {
		seen[rec.ID] = struct{}{}
		return nil
	})
	require.NoError(t, err)

	for _, id := range ids {
		_, ok := seen[id]
		assert.True(t, ok, "Walk must visit %s", id)
	}
	assert.Len(t, seen, len(ids))
}

func TestStore_Walk_PropagatesCallbackError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := assessment.NewStore(&config.AppConfig{AssessmentsDir: dir})
	require.NoError(t, store.Save(assessment.Record{ID: "CVE-2024-0001"}))

	sentinel := errors.New("boom")
	err := store.Walk(t.Context(), func(assessment.Record) error {
		return sentinel
	})
	require.ErrorIs(t, err, sentinel)
}

func TestStore_Walk_FailsOnMismatchedIdentity(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := assessment.NewStore(&config.AppConfig{AssessmentsDir: dir})

	// Write a record whose file name does not match its declared ID.
	path := filepath.Join(dir, "2024", "0xxx", "CVE-2024-0001.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(`{"id":"CVE-2024-0002"}`), 0o644))

	err := store.Walk(t.Context(), func(assessment.Record) error { return nil })
	require.ErrorIs(t, err, assessment.ErrRecordIDMismatch)
}

func TestStore_Walk_FailsOnCorruptRecord(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := assessment.NewStore(&config.AppConfig{AssessmentsDir: dir})

	path := filepath.Join(dir, "2024", "0xxx", "CVE-2024-0001.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(`{not json`), 0o644))

	err := store.Walk(t.Context(), func(assessment.Record) error { return nil })
	require.Error(t, err)
}

func TestStore_Walk_HonorsContextCancellation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := assessment.NewStore(&config.AppConfig{AssessmentsDir: dir})
	require.NoError(t, store.Save(assessment.Record{ID: "CVE-2024-0001"}))

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	err := store.Walk(ctx, func(assessment.Record) error { return nil })
	require.ErrorIs(t, err, context.Canceled)
}
