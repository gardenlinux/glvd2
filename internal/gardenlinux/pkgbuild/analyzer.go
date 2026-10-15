package pkgbuild

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/gardenlinux/glvd2/internal/purl"
)

// ErrNotFound reports that a requested item does not exist.
var ErrNotFound = errors.New("not found")

// ErrAlreadyStored reports an attempt to save an [Analysis] that is already present.
var ErrAlreadyStored = errors.New("analysis already stored")

// Fetcher reads build inputs from a GL package repo at a given git ref.
type Fetcher interface {
	// CommitForTag returns the commit sha a tag points at or ErrNotFound.
	CommitForTag(ctx context.Context, repo, tag string) (sha string, err error)
	// File returns a text file's content at ref, or ErrNotFound.
	File(ctx context.Context, repo, path, ref string) (content string, err error)
}

// Analyzer resolves and persists per-pkg-build analyses.
type Analyzer struct {
	store   *Store
	fetcher Fetcher
	run     map[string]Analysis
}

// NewAnalyzer builds an [Analyzer] over a store and fetcher.
func NewAnalyzer(store *Store, fetcher Fetcher) *Analyzer {
	return &Analyzer{
		store:   store,
		fetcher: fetcher,
		run:     map[string]Analysis{},
	}
}

// Analyze returns the analysis for a shipped (source pkg name, version),
// computing and persisting it on first encounter and reusing it afterwards.
func (a *Analyzer) Analyze(ctx context.Context, pkgName, version string) (Analysis, error) {
	// First check the memoization cache for the current run; then the on-disk storage.
	runKey := pkgName + "\x00" + storeVersion(version)
	if analysis, ok := a.run[runKey]; ok {
		return analysis, nil
	}

	switch analysis, err := a.store.Lookup(pkgName, version); {
	case err == nil:
		a.run[runKey] = analysis
		return analysis, nil
	case !errors.Is(err, ErrNotFound):
		return Analysis{}, err
	}

	analysis, err := a.resolve(ctx, pkgName, version)
	if err != nil {
		return Analysis{}, err
	}

	if saveErr := a.store.Save(analysis); saveErr != nil {
		return Analysis{}, saveErr
	}
	a.run[runKey] = analysis

	return analysis, nil
}

// resolve computes a fresh analysis by locating the version's git tag
// and reading prepare_source and the applied patch folders at that commit.
func (a *Analyzer) resolve(ctx context.Context, pkgName, version string) (Analysis, error) {
	base := Analysis{
		PkgName: pkgName,
		Version: storeVersion(version),
		PURL:    purl.GardenLinuxIdentity(pkgName),
	}

	tag := versionToTag(version)
	repo, sha, err := a.locate(ctx, pkgName, version, tag)
	if errors.Is(err, ErrNotFound) {
		// No repo or no matching tag: not built by GL -> ships pkg from Debian as-is.
		base.Provenance = classify(BuildSignals{})

		return base, nil
	}
	if err != nil {
		return Analysis{}, err
	}
	base.Repo = repo
	base.TagCommit = sha

	content, err := a.fetcher.File(ctx, repo, "prepare_source", sha)
	if errors.Is(err, ErrNotFound) {
		// Tag exists but carries no build recipe: treat as a non-GL-built pool import.
		base.Provenance = classify(BuildSignals{})

		return base, nil
	}
	if err != nil {
		return Analysis{}, fmt.Errorf("fetching prepare_source for %s@%s: %w", repo, sha, err)
	}

	prepared := prepareScriptContent(content)
	base.Signals = analyzeRecipe(prepared)
	base.Provenance = classify(base.Signals)

	fixed, err := a.patchedCVEs(ctx, repo, sha, prepared)
	if err != nil {
		return Analysis{}, err
	}
	base.FixedCVEs = fixed

	return base, nil
}

// locate finds the repo and commit hosting the version's tag, trying the candidate repo names in order.
// It returns ErrNotFound when no candidate has the tag.
func (a *Analyzer) locate(ctx context.Context, pkgName, version, tag string) (string, string, error) {
	for _, repo := range repoCandidates(pkgName, version) {
		sha, err := a.fetcher.CommitForTag(ctx, repo, tag)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return "", "", fmt.Errorf("resolving tag %s in %s: %w", tag, repo, err)
		}

		return repo, sha, nil
	}

	return "", "", ErrNotFound
}

// patchedCVEs scans the applied patch folders' quilt series for CVE-named patches.
func (a *Analyzer) patchedCVEs(ctx context.Context, repo, ref, prepared string) ([]FixedCVE, error) {
	seen := map[string]bool{}
	var fixed []FixedCVE

	for _, dir := range appliedPatchDirs(prepared) {
		if !safePatchDir(dir) {
			slog.Warn("skipping unsafe patch dir", slog.String("repo", repo), slog.String("dir", dir))
			continue
		}

		series, err := a.fetcher.File(ctx, repo, dir+"/series", ref)
		if errors.Is(err, ErrNotFound) {
			slog.Warn("no quilt series in patch dir", slog.String("repo", repo), slog.String("dir", dir))
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("fetching %s/series for %s@%s: %w", dir, repo, ref, err)
		}

		for _, cve := range cvesFromSeries(series) {
			if seen[cve.ID] {
				continue
			}
			seen[cve.ID] = true
			fixed = append(fixed, cve)
		}
	}

	return fixed, nil
}
