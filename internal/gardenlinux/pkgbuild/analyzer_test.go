package pkgbuild_test

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"testing"

	"github.com/gardenlinux/glvd2/internal/config"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/pkgbuild"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeFetcher serves prepare_source and series content keyed by "repo@ref:path".
// It records request counts to assert dedup behavior.
type fakeFetcher struct {
	tags  map[string]string // "repo@tag" -> sha ("" means not found)
	files map[string]string // "repo@tag:path" -> content (absent means not found)

	commitCalls map[string]int
	fileCalls   map[string]int
}

func newFakeFetcher() *fakeFetcher {
	return &fakeFetcher{
		tags:        map[string]string{},
		files:       map[string]string{},
		commitCalls: map[string]int{},
		fileCalls:   map[string]int{},
	}
}

func (f *fakeFetcher) CommitForTag(_ context.Context, repo, tag string) (string, error) {
	key := repo + "@" + tag
	f.commitCalls[key]++
	sha, ok := f.tags[key]
	if !ok || sha == "" {
		return "", pkgbuild.ErrNotFound
	}

	return sha, nil
}

func (f *fakeFetcher) File(_ context.Context, repo, path, ref string) (string, error) {
	key := repo + "@" + ref + ":" + path
	f.fileCalls[key]++
	content, ok := f.files[key]
	if !ok {
		return "", pkgbuild.ErrNotFound
	}

	return content, nil
}

func newAnalyzer(t *testing.T, f pkgbuild.Fetcher) *pkgbuild.Analyzer {
	t.Helper()
	cfg := &config.AppConfig{PkgBuildStoreDir: t.TempDir()}

	return pkgbuild.NewAnalyzer(pkgbuild.NewStore(cfg), f)
}

type analyzeCase struct {
	Input struct {
		SourcePkgName string `json:"source_pkg_name"`
		Version       string `json:"version"`
	} `json:"input"`
	Tags map[string]string `json:"tags"`
	// Expected is the full serialized Analysis against which we compare.
	Expected json.RawMessage `json:"expected"`
}

// loadAnalyzeCase reads a test case fixture and builds a fakeFetcher from its repos tree.
func loadAnalyzeCase(t *testing.T, dir string) (analyzeCase, *fakeFetcher) {
	t.Helper()

	casePath := filepath.Join(dir, "case.json")
	data, err := os.ReadFile(casePath) //nolint:gosec // reads fixture files from a fixed testdata tree
	require.NoError(t, err)

	var tc analyzeCase
	require.NoError(t, json.Unmarshal(data, &tc))

	f := newFakeFetcher()
	maps.Copy(f.tags, tc.Tags)

	reposDir := filepath.Join(dir, "repos")
	entries, err := os.ReadDir(reposDir)
	if errors.Is(err, fs.ErrNotExist) {
		return tc, f
	}
	require.NoError(t, err)

	for _, repoTag := range entries {
		root := filepath.Join(reposDir, repoTag.Name())
		walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return relErr
			}
			content, readErr := os.ReadFile(path) //nolint:gosec // reads fixture files from a fixed testdata tree
			if readErr != nil {
				return readErr
			}
			f.files[repoTag.Name()+":"+filepath.ToSlash(rel)] = string(content)
			return nil
		})
		require.NoError(t, walkErr)
	}

	return tc, f
}

func TestAnalyze(t *testing.T) {
	t.Parallel()

	const casesDir = "testdata/analyze"
	cases, dirErr := os.ReadDir(casesDir)
	require.NoError(t, dirErr)

	for _, c := range cases {
		if !c.IsDir() {
			continue
		}
		t.Run(c.Name(), func(t *testing.T) {
			t.Parallel()

			tc, f := loadAnalyzeCase(t, filepath.Join(casesDir, c.Name()))

			an, err := newAnalyzer(t, f).Analyze(t.Context(), tc.Input.SourcePkgName, tc.Input.Version)
			require.NoError(t, err)

			actualJSON, err := json.Marshal(an)
			require.NoError(t, err)
			assert.JSONEq(t, string(tc.Expected), string(actualJSON))
		})
	}
}

func TestAnalyze_DedupWithinRun(t *testing.T) {
	t.Parallel()

	f := newFakeFetcher()
	f.tags["package-openssl@1-1gl1"] = "sha"
	f.files["package-openssl@sha:prepare_source"] = "apt_src openssl\n"

	a := newAnalyzer(t, f)
	for range 3 {
		_, err := a.Analyze(t.Context(), "openssl", "1-1gl1")
		require.NoError(t, err)
	}

	// A binNMU of the same base resolves to the same entry without new fetches.
	_, err := a.Analyze(t.Context(), "openssl", "1-1gl1+b1")
	require.NoError(t, err)

	assert.Equal(t, 1, f.commitCalls["package-openssl@1-1gl1"])
	assert.Equal(t, 1, f.fileCalls["package-openssl@sha:prepare_source"])
}

func TestAnalyze_DedupAcrossRunsViaStore(t *testing.T) {
	t.Parallel()

	f := newFakeFetcher()
	f.tags["package-openssl@1-1gl1"] = "sha"
	f.files["package-openssl@sha:prepare_source"] = "apt_src openssl\n"

	cfg := &config.AppConfig{PkgBuildStoreDir: t.TempDir()}
	store := pkgbuild.NewStore(cfg)

	_, err := pkgbuild.NewAnalyzer(store, f).Analyze(t.Context(), "openssl", "1-1gl1")
	require.NoError(t, err)

	// A fresh analyzer (new run) sharing the store must not refetch.
	_, err = pkgbuild.NewAnalyzer(store, f).Analyze(t.Context(), "openssl", "1-1gl1")
	require.NoError(t, err)

	assert.Equal(t, 1, f.commitCalls["package-openssl@1-1gl1"])
}
