package presentation_test

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/flavorinventory"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/gltest"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/packages"
	"github.com/gardenlinux/glvd2/internal/presentation"
	"github.com/gardenlinux/glvd2/internal/purl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sliceSource is an in-memory RecordWalker that walks a fixed slice of records in order.
type sliceSource []assessment.Record

func (s sliceSource) Walk(ctx context.Context, fn func(assessment.Record) error) error {
	for _, rec := range s {
		if err := ctx.Err(); err != nil {
			return err
		}

		if err := fn(rec); err != nil {
			return err
		}
	}

	return nil
}

type walkFunc func(context.Context, func(assessment.Record) error) error

func (f walkFunc) Walk(ctx context.Context, fn func(assessment.Record) error) error {
	return f(ctx, fn)
}

// glID returns the gardenlinux-namespaced source identity PURL for a source name.
func glID(name string) string {
	return "pkg:deb/gardenlinux/" + name
}

// debID returns the debian-namespaced source identity PURL for a source name.
func debID(name string) string {
	return "pkg:deb/debian/" + name
}

// gldeb builds a gardenlinux-namespaced deb component whose source is the given name.
func gldeb(source string) cdx.Component {
	return gltest.DebComponent(packages.Package{
		Name:      source + "-bin",
		Source:    source,
		Namespace: purl.NamespaceGardenLinux,
	})
}

// inventory builds a flavor inventory from release -> flavor -> source names through the real accumulator,
// so membership is produced exactly as the pipeline produces it.
func inventory(tb testing.TB, spec map[string]map[string][]string) flavorinventory.Inventory {
	tb.Helper()

	acc := flavorinventory.NewAccumulator()
	for _, rel := range slices.Sorted(maps.Keys(spec)) {
		flavors := spec[rel]

		for _, fl := range slices.Sorted(maps.Keys(flavors)) {
			comps := make([]cdx.Component, 0, len(flavors[fl]))

			for _, src := range flavors[fl] {
				comps = append(comps, gldeb(src))
			}

			require.NoError(tb, acc.AddSBOM(rel, fl, gltest.BOM(comps...)))
		}
	}

	return acc.Result()
}

// relevantRecord builds an effectively relevant record with the given per-release decisions.
func relevantRecord(id string, releases map[string]assessment.ReleaseDecision) assessment.Record {
	return assessment.Record{
		ID: id,
		Screening: assessment.ScreeningResult{
			AutoTriage: assessment.AutoTriage{Reason: assessment.TriageReasonAffectsDebianPackage},
		},
		Releases: releases,
	}
}

// notRelevantRecord builds a record screened out by the global gate.
func notRelevantRecord(id string, releases map[string]assessment.ReleaseDecision) assessment.Record {
	return assessment.Record{
		ID: id,
		Screening: assessment.ScreeningResult{
			AutoTriage: assessment.AutoTriage{Reason: assessment.TriageReasonRejectedUpstream},
		},
		Releases: releases,
	}
}

// undecidedRecord builds a record left undecided (awaiting a decision).
func undecidedRecord(id string) assessment.Record {
	return assessment.Record{
		ID: id,
		Screening: assessment.ScreeningResult{
			AutoTriage: assessment.AutoTriage{Reason: assessment.TriageReasonAwaitingDebian},
		},
	}
}

// autoPkg builds a per-package auto status with only a reason.
func autoPkg(reason assessment.ReleaseStatusReason) assessment.PackageStatus {
	return assessment.PackageStatus{Reason: reason}
}

// override builds a per-package manual override with only a status.
func override(status assessment.ReleaseStatus) assessment.PackageOverride {
	return assessment.PackageOverride{Status: status}
}

// decision builds a release decision from auto and manual package maps.
func decision(
	auto map[string]assessment.PackageStatus,
	manual map[string]assessment.PackageOverride,
) assessment.ReleaseDecision {
	return assessment.ReleaseDecision{
		Auto:   assessment.AutoReleaseStatus{Packages: auto},
		Manual: assessment.ManualReleaseStatus{Packages: manual},
	}
}

// autoDecision builds a release decision with only auto per-package statuses.
func autoDecision(auto map[string]assessment.PackageStatus) assessment.ReleaseDecision {
	return decision(auto, nil)
}

// render writes a site for the given inventory, maintained releases, and records, failing the test
// on error, and returns the completed result.
func render(
	tb testing.TB,
	inv flavorinventory.Inventory,
	maintained []string,
	recs ...assessment.Record,
) presentation.Result {
	tb.Helper()

	s, err := presentation.NewRenderer(presentation.RenderConfig{OutDir: tb.TempDir()})
	require.NoError(tb, err)

	res, err := s.Render(tb.Context(), sliceSource(recs), inv, maintained)
	require.NoError(tb, err)

	return res
}

// readCVEPage reads the rendered CVE detail page under outDir.
func readCVEPage(t *testing.T, outDir, id string) string {
	t.Helper()

	return readFile(t, pageFor(outDir, id))
}

func releasePath(version string) string {
	return "releases/" + version + "/index.html"
}

func flavorPath(version, flavor string) string {
	return "releases/" + version + "/flavors/" + flavor + "/index.html"
}

func packagePath(name string) string {
	return "packages/" + name + "/index.html"
}

// buildCVEs builds n relevant records with sequential IDs and the same release decisions.
func buildCVEs(n int, releases map[string]assessment.ReleaseDecision) []assessment.Record {
	recs := make([]assessment.Record, 0, n)

	for i := 1; i <= n; i++ {
		recs = append(recs, relevantRecord(idForSeq(i), releases))
	}

	return recs
}

// pageFor returns the path of a CVE detail page under outDir.
func pageFor(outDir, id string) string {
	return filepath.Join(outDir, "cves", id, "index.html")
}

// collectTree reads every file under root into a map of root-relative path to contents.
func collectTree(t *testing.T, root string) map[string]string {
	t.Helper()

	tree := make(map[string]string)

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		data, readErr := os.ReadFile(path) //nolint:gosec // test temp dir
		if readErr != nil {
			return readErr
		}
		tree[rel] = string(data)

		return nil
	})
	require.NoError(t, err)

	return tree
}

func assertFileExists(t *testing.T, path string) {
	t.Helper()

	_, err := os.Stat(path)
	assert.NoError(t, err, "expected file to exist: %s", path)
}

func assertFileNotExists(t *testing.T, path string) {
	t.Helper()

	_, err := os.Stat(path)
	assert.True(t, os.IsNotExist(err), "expected file not to exist: %s", path)
}

func readFile(t *testing.T, path string) string {
	t.Helper()

	data, err := os.ReadFile(path) //nolint:gosec // test helper reads from caller-controlled path
	require.NoError(t, err, "reading %s", path)

	return string(data)
}

// idForSeq returns a deterministic CVE ID for a 1-based sequence number.
func idForSeq(i int) string {
	return "CVE-2024-" + strconv.Itoa(1000+i)
}
