package presentation_test

import (
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"testing"

	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/gardenlinux/glvd2/internal/presentation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRenderer_MalformedPackageIdentityFails(t *testing.T) {
	t.Parallel()

	rec := relevantRecord("CVE-2024-0001", map[string]assessment.ReleaseDecision{
		"1877.26": autoDecision(map[string]assessment.PackageStatus{
			"not-a-purl": autoPkg(assessment.ReleaseReasonVersionVulnerable),
		}),
	})

	s, err := presentation.NewRenderer(presentation.RenderConfig{OutDir: t.TempDir()})
	require.NoError(t, err)

	_, err = s.Render(t.Context(), sliceSource{rec}, inventory(t, nil), []string{"1877.26"})
	require.ErrorContains(t, err, "not-a-purl")
}

func TestRenderer_DoesNotMutateAssessments(t *testing.T) {
	t.Parallel()

	inv := inventory(t, map[string]map[string][]string{"1877.26": {"kvm": {"openssl"}}})

	original := relevantRecord("CVE-2024-0001", map[string]assessment.ReleaseDecision{
		"1877.26": decision(
			map[string]assessment.PackageStatus{
				glID("openssl"): autoPkg(assessment.ReleaseReasonVersionVulnerable),
				glID("aws-cli"): autoPkg(assessment.ReleaseReasonAffectedEscalated),
			},
			map[string]assessment.PackageOverride{glID("openssl"): override(assessment.ReleaseStatusNotAffected)},
		),
	})
	snapshot := cloneDecisions(original.Releases)

	render(t, inv, []string{"1877.26"}, original)

	assert.Equal(t, snapshot, original.Releases)
}

func cloneDecisions(in map[string]assessment.ReleaseDecision) map[string]assessment.ReleaseDecision {
	out := make(map[string]assessment.ReleaseDecision, len(in))

	for rel, rd := range in {
		out[rel] = assessment.ReleaseDecision{
			Auto:   assessment.AutoReleaseStatus{Packages: maps.Clone(rd.Auto.Packages)},
			Manual: assessment.ManualReleaseStatus{Packages: maps.Clone(rd.Manual.Packages)},
		}
	}

	return out
}

func TestRenderer_UniqueRunDirectories(t *testing.T) {
	t.Parallel()

	parent := t.TempDir()
	s, err := presentation.NewRenderer(presentation.RenderConfig{OutDir: parent})
	require.NoError(t, err)

	first, err := s.Render(t.Context(), sliceSource(nil), inventory(t, nil), nil)
	require.NoError(t, err)

	second, err := s.Render(t.Context(), sliceSource(nil), inventory(t, nil), nil)
	require.NoError(t, err)

	assert.NotEqual(t, first.OutDir, second.OutDir)
	assert.Equal(t, parent, filepath.Dir(first.OutDir), "run directory is created under the configured parent")
}

func TestRenderer_OutputPermissions(t *testing.T) {
	t.Parallel()

	for _, outcome := range []string{"complete", "partial"} {
		t.Run(outcome, func(t *testing.T) {
			t.Parallel()

			parent := filepath.Join(t.TempDir(), "site")
			require.NoError(t, os.Mkdir(parent, 0o755))

			// Reference modes account for umask without changing process-global state.
			dirInfo, err := os.Stat(parent)
			require.NoError(t, err)

			reference := filepath.Join(t.TempDir(), "reference")
			require.NoError(t, os.WriteFile(reference, nil, 0o644))

			fileInfo, err := os.Stat(reference)
			require.NoError(t, err)

			s, err := presentation.NewRenderer(presentation.RenderConfig{OutDir: parent})
			require.NoError(t, err)

			sourceErr := errors.New("source failed")
			src := walkFunc(func(_ context.Context, fn func(assessment.Record) error) error {
				if callbackErr := fn(relevantRecord("CVE-2024-0001", nil)); callbackErr != nil {
					return callbackErr
				}
				if outcome == "partial" {
					return sourceErr
				}
				return nil
			})

			_, err = s.Render(t.Context(), src, inventory(t, nil), nil)

			if outcome == "partial" {
				require.ErrorIs(t, err, sourceErr)
			} else {
				require.NoError(t, err)
			}

			out := onlyRunDir(t, parent)
			require.NoError(t, filepath.WalkDir(out, func(path string, entry os.DirEntry, err error) error {
				if err != nil {
					return err
				}

				info, err := entry.Info()
				if err != nil {
					return err
				}

				want := fileInfo.Mode().Perm()
				if path == out {
					want = 0o755
				} else if entry.IsDir() {
					want = dirInfo.Mode().Perm()
				}

				assert.Equal(t, want, info.Mode().Perm(), path)

				return nil
			}))
		})
	}
}

func TestRenderer_WritesCVEPagesDuringSingleWalk(t *testing.T) {
	t.Parallel()

	parent := t.TempDir()

	s, err := presentation.NewRenderer(presentation.RenderConfig{OutDir: parent})
	require.NoError(t, err)

	walks := 0
	src := walkFunc(func(_ context.Context, fn func(assessment.Record) error) error {
		walks++
		require.Equal(t, 1, walks)

		for _, rec := range buildCVEs(2, nil) {
			if callbackErr := fn(rec); callbackErr != nil {
				return callbackErr
			}
			assertFileExists(t, pageFor(onlyRunDir(t, parent), rec.ID))
		}

		return nil
	})

	_, err = s.Render(t.Context(), src, inventory(t, nil), nil)
	require.NoError(t, err)

	assert.Equal(t, 1, walks)
}

func TestRenderer_FailurePreservesPartialOutputWithoutDeployableResult(t *testing.T) {
	t.Parallel()

	sourceErr := errors.New("source failed")
	for _, outcome := range []string{"invalid CVE", "source error"} {
		t.Run(outcome, func(t *testing.T) {
			t.Parallel()

			parent := t.TempDir()

			s, err := presentation.NewRenderer(presentation.RenderConfig{OutDir: parent})
			require.NoError(t, err)

			rec := relevantRecord("CVE-2024-0001", nil)

			src := walkFunc(func(_ context.Context, fn func(assessment.Record) error) error {
				if callbackErr := fn(rec); callbackErr != nil {
					return callbackErr
				}
				if outcome == "invalid CVE" {
					return fn(assessment.Record{ID: "../invalid"})
				}
				return sourceErr
			})

			res, err := s.Render(t.Context(), src, inventory(t, nil), nil)
			require.Error(t, err)

			if outcome == "source error" {
				require.ErrorIs(t, err, sourceErr)
			}

			assert.Empty(t, res.OutDir)
			assertFileExists(t, pageFor(onlyRunDir(t, parent), rec.ID))
		})
	}
}

func onlyRunDir(t *testing.T, parent string) string {
	t.Helper()

	entries, err := os.ReadDir(parent)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.True(t, entries[0].IsDir())

	return filepath.Join(parent, entries[0].Name())
}

func TestRenderer_ContextCancellationStopsRender(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	parent := t.TempDir()
	s, err := presentation.NewRenderer(presentation.RenderConfig{OutDir: parent})
	require.NoError(t, err)

	src := walkFunc(func(_ context.Context, fn func(assessment.Record) error) error {
		if callbackErr := fn(relevantRecord("CVE-2024-0001", nil)); callbackErr != nil {
			return callbackErr
		}
		cancel()
		callbackErr := fn(relevantRecord("CVE-2024-0002", nil))
		require.ErrorIs(t, callbackErr, context.Canceled, "the renderer callback must stop the walk")
		return callbackErr
	})

	res, err := s.Render(ctx, src, inventory(t, nil), nil)
	require.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, res.OutDir)

	entries, err := os.ReadDir(parent)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	out := filepath.Join(parent, entries[0].Name())

	assertFileExists(t, pageFor(out, "CVE-2024-0001"))
	assertFileNotExists(t, pageFor(out, "CVE-2024-0002"))
	assertFileNotExists(t, filepath.Join(out, "index.html"))
}

func TestNewRenderer_EmptyOutDirIsRejected(t *testing.T) {
	t.Parallel()

	_, err := presentation.NewRenderer(presentation.RenderConfig{OutDir: ""})
	require.Error(t, err)
}
