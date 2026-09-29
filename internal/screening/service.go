package screening

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"

	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/inventory"
	"github.com/gardenlinux/glvd2/internal/glmap"
	"github.com/gardenlinux/glvd2/internal/ingestion/cvelistv5"
	"github.com/gardenlinux/glvd2/internal/ingestion/debsectracker"
	"github.com/gardenlinux/glvd2/internal/model/debtriage"
	"github.com/gardenlinux/glvd2/internal/purl"
	"github.com/gardenlinux/glvd2/internal/repository"
)

// DebianVerdictLookup returns the per-CVE Debian triage entry.
type DebianVerdictLookup interface {
	GetTriageEntryFromDB(ctx context.Context, cveID string) (*debsectracker.TriageEntry, error)
}

// Service assembles the per-CVE screening inputs and calls the pure [Screen].
type Service struct {
	curated   glmap.Rules
	vendored  glmap.Rules
	inventory inventory.Set
	debian    DebianVerdictLookup
	ids       cvelistv5.IDsForCVEs
}

// NewService constructs a screening service from its already-built inputs.
func NewService(
	curated glmap.Rules,
	vendored glmap.Rules,
	inv inventory.Set,
	debian DebianVerdictLookup,
	ids cvelistv5.IDsForCVEs,
) *Service {
	return &Service{
		curated:   curated,
		vendored:  vendored,
		inventory: inv,
		debian:    debian,
		ids:       ids,
	}
}

// Screen returns the screening verdict for the record.
func (s *Service) Screen(ctx context.Context, rec assessment.Record) (assessment.ScreeningResult, error) {
	in := Input{Rejected: rec.Upstream.State == assessment.CVEStateRejected}

	if ids := s.ids[rec.ID]; ids != nil {
		in.CuratedMatches = s.curated.Lookup(*ids)
		in.VendoredMatches = s.vendored.Lookup(*ids)
	}

	if err := s.applyDebianVerdict(ctx, rec.ID, &in); err != nil {
		return assessment.ScreeningResult{}, err
	}

	return Screen(in), nil
}

// applyDebianVerdict folds Debian's per-CVE verdict into the input.
func (s *Service) applyDebianVerdict(ctx context.Context, cveID string, in *Input) error {
	entry, err := s.debian.GetTriageEntryFromDB(ctx, cveID)
	if errors.Is(err, sql.ErrNoRows) {
		// A missing verdict is expected, not a failure.
		return nil
	}
	if err != nil {
		return fmt.Errorf("fetching Debian verdict for %s: %w", cveID, err)
	}

	if entry.Triage.Status == debtriage.StatusNotForUs {
		in.DebianNotForUs = true
		return nil
	}

	if len(entry.AffectedPackages) == 0 {
		return nil
	}

	purls, err := debianPURLs(entry.AffectedPackages)
	if err != nil {
		return fmt.Errorf("building Debian PURLs for %s: %w", cveID, err)
	}

	shipped, err := s.shippedSubset(purls)
	if err != nil {
		return fmt.Errorf("resolving shipped subset for %s: %w", cveID, err)
	}

	in.DebianAssigned = true
	in.DebianAllPURLs = purls
	in.DebianShipped = shipped

	return nil
}

// shippedSubset returns the PURLs present in the GL inventory.
func (s *Service) shippedSubset(purls []string) ([]string, error) {
	var shipped []string
	for _, p := range purls {
		ok, err := s.inventory.Contains(p)
		if err != nil {
			return nil, fmt.Errorf("inventory membership check for %q: %w", p, err)
		}
		if ok {
			shipped = append(shipped, p)
		}
	}

	return shipped, nil
}

// debianPURLs returns canonical identity PURLs for Debian's affected source packages,
// deduplicated and sorted.
func debianPURLs(pkgs []repository.DebianTriageAffectedPackage) ([]string, error) {
	out := make([]string, 0, len(pkgs))
	for _, pkg := range pkgs {
		canon, err := purl.Canonicalize("pkg:deb/debian/" + pkg.PackageName)
		if err != nil {
			return nil, fmt.Errorf("canonicalizing Debian package PURL %q: %w", pkg.PackageName, err)
		}
		out = append(out, canon)
	}

	slices.Sort(out)

	return slices.Compact(out), nil
}
