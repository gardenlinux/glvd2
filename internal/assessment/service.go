// Package assessment manages CVE assessment records as JSON files.
//
// It provides the core types ([Record], [Triage], [ReleaseTriage], [ReleaseDecision]),
// file I/O with CVEListV5-compatible bucketing ([Store]), git-based baseline tracking
// ([Baseline]), strategy-driven merge logic, field-level diffing, and a [Reactor]
// interface for side effects on changes.
//
// Field ownership is encoded via struct tags (merge:"...") on [Record] fields
// and drives merge and diff behavior automatically:
//   - key: identity field, never changed
//   - overwrite: always taken from incoming data
//   - preserve: never touched by the program (human/bot-managed)
//   - map,preserve: per-key struct merge; keys not in incoming are kept
//   - map,replace: per-key struct merge; keys not in incoming are removed
package assessment

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
)

// Service orchestrates the full CVE assessment record pipeline: loading existing state,
// merging incoming data, diffing against baseline, saving, and running reactors.
type Service struct {
	mergeSpecCache  *mergeSpec
	store           *Store
	baseline        *Baseline
	reactors        []Reactor
	extModifiedCVEs map[string]struct{}
}

// NewService creates a Service that manages the full CVE data pipeline.
// It pre-loads the set of externally modified files from the baseline for optimization.
func NewService(
	ctx context.Context, store *Store, baseline *Baseline, reactors []Reactor,
) (*Service, error) {
	cache := newMergeSpec[Record]() // cached Assessment reflections

	return &Service{
		mergeSpecCache:  cache,
		store:           store,
		baseline:        baseline,
		reactors:        reactors,
		extModifiedCVEs: loadExternallyModifiedCVEs(ctx, baseline),
	}, nil
}

// loadExternallyModifiedCVEs returns the set of CVE IDs modified externally since the last baseline commit.
// It returns nil if the diff failed or if there it is the first run and empty records should be used as baseline.
func loadExternallyModifiedCVEs(ctx context.Context, baseline *Baseline) map[string]struct{} {
	// on a first run everything should be treated as new (empty record as baseline)
	if baseline.IsFirstRun() {
		return nil
	}

	changedFiles, err := baseline.ExternallyModifiedFiles(ctx)
	if err != nil {
		slog.Warn("failed to list externally modified files, will load baseline for all CVEs",
			slog.Any("error", err))
		return nil
	}

	extModifiedCVEs := make(map[string]struct{}, len(changedFiles))
	for _, f := range changedFiles {
		// Extract CVE ID from path like "data/cves/2025/1xxx/CVE-2025-1234.json".
		base := filepath.Base(f)
		id := strings.TrimSuffix(base, ".json")
		if _, _, idErr := parseCVEID(id); idErr != nil {
			slog.Warn("skipping externally modified file with invalid CVE ID",
				slog.String("path", f), slog.Any("error", idErr))
			continue
		}

		extModifiedCVEs[id] = struct{}{}
	}

	if len(extModifiedCVEs) > 0 {
		slog.Info("externally modified CVEs detected", slog.Int("count", len(extModifiedCVEs)))
	}

	return extModifiedCVEs
}

// Process handles a single incoming assessment record through the full pipeline:
// load existing from disk, merge, diff against baseline, run reactors, save if changed.
func (s *Service) Process(ctx context.Context, incoming Record) (Record, ChangeSet, error) {
	existing, err := s.store.Get(incoming.ID)
	if err != nil && !errors.Is(err, ErrRecordNotFound) {
		return Record{}, ChangeSet{}, fmt.Errorf("loading existing assessment record: %w", err)
	}

	merged, err := mergeRecords(s.mergeSpecCache, existing, incoming)
	if err != nil {
		return Record{}, ChangeSet{}, fmt.Errorf("merging assessment record: %w", err)
	}

	baseline, err := s.resolveBaseline(ctx, incoming.ID, existing)
	if err != nil {
		return Record{}, ChangeSet{}, fmt.Errorf("loading baseline assessment record: %w", err)
	}

	// If an external actor modified a program-owned (overwrite) field,
	// show a warning (since this should not happen and will be reverted).
	//
	// Merged will have dropped these external changes, since they are marked for overwriting,
	// so the reactor diff (between baseline and merged) will not show them.
	anomalyDiff := detectExternalOverwriteEdits(s.mergeSpecCache, baseline, existing)
	hasExternalModification := false
	if len(anomalyDiff) > 0 {
		hasExternalModification = true

		attrs := make([]slog.Attr, 0, len(anomalyDiff)+1)
		attrs = append(attrs, slog.String("cve", incoming.ID))
		for i, e := range anomalyDiff {
			attrs = append(attrs, slog.Group(
				fmt.Sprintf("fields[%d]", i),
				slog.String("field", e.Field.String()),
				slog.String("expected_value", e.OldValue),
				slog.String("current_value", e.NewValue),
			))
		}
		slog.LogAttrs(
			ctx,
			slog.LevelWarn,
			"external actor modified program-owned fields (will be ignored and reverted)",
			attrs...)
	}

	reactorDiff := diffRecords(s.mergeSpecCache, baseline, merged)
	if !reactorDiff.HasChanges() && !hasExternalModification {
		return merged, reactorDiff, nil // nothing to save or react to
	}

	if reactorDiff.HasChanges() {
		for _, r := range s.reactors {
			if reactErr := r.React(ctx, baseline, &merged, reactorDiff); reactErr != nil {
				return Record{}, ChangeSet{}, fmt.Errorf("reactor failed for %s: %w", incoming.ID, reactErr)
			}
		}
	}

	if saveErr := s.store.Save(merged); saveErr != nil {
		return Record{}, ChangeSet{}, fmt.Errorf("saving merged assessment record: %w", saveErr)
	}

	return merged, reactorDiff, nil
}

// resolveBaseline determines the baseline assessment record to diff against.
// If extModifiedFiles is not nil and the CVE is not in it, the on-disk state equals the
// baseline and is used directly (avoids loading all >300k files via git).
// Otherwise the baseline is loaded via git (empty record on first run).
func (s *Service) resolveBaseline(ctx context.Context, cveID string, existing Record) (Record, error) {
	if s.extModifiedCVEs != nil {
		if _, modified := s.extModifiedCVEs[cveID]; !modified {
			return existing, nil // not modified externally: on-disk state equals baseline
		}
	}

	baseline, err := s.baseline.LoadAssessmentRecord(ctx, cveID)
	if err != nil {
		// should only happen if something is wrong with receiving from git
		return Record{}, fmt.Errorf("failed to load baseline assessment record for %q: %w", cveID, err)
	}

	return baseline, nil
}
