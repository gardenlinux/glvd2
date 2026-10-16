// Package affectedness determines whether and where a shipped source package is
// affected by a given CVE, taking into account how the package was built.
package affectedness

import (
	"context"
	"errors"
	"fmt"

	"github.com/gardenlinux/glvd2/internal/gardenlinux/pkgbuild"
	"github.com/gardenlinux/glvd2/internal/model/cve_v5"
	"github.com/gardenlinux/glvd2/internal/purl"
	"github.com/git-pkgs/vers"
)

// Outcome is the facts-only decision for a matched source package.
type Outcome string

const (
	// OutcomeFixed - build fix-evidence shows the CVE is patched in the shipped build.
	OutcomeFixed Outcome = "fixed"
	// OutcomeVersionRange - a vulnerable [Result.Range] was built (compare the shipped version against it).
	OutcomeVersionRange Outcome = "version-range"
	// OutcomeNotAffected - a confident authority decision that the package is not vulnerable.
	OutcomeNotAffected Outcome = "not-affected"
	// OutcomeAffectedNoRange - presumed vulnerable with no fix version to compare against.
	OutcomeAffectedNoRange Outcome = "affected-no-range"
	// OutcomeUndecided - no usable authority decided.
	OutcomeUndecided Outcome = "undecided"
)

// Authority names which input (pkg-build, Debian, or upstream) decided the outcome.
type Authority string

const (
	// AuthorityNone is the zero value, used for [OutcomeUndecided].
	AuthorityNone Authority = ""
	// AuthorityPkgBuild is the build's own fix-evidence.
	AuthorityPkgBuild Authority = "pkg-build"
	// AuthorityDebian is the Debian verdict.
	AuthorityDebian Authority = "debian"
	// AuthorityUpstream is the CVE record's own version signals.
	AuthorityUpstream Authority = "upstream"
)

// Basis records how the outcome was decided.
type Basis string

const (
	// BasisFixEvidence - a CVE-named patch fixes the CVE in the build.
	BasisFixEvidence Basis = "fix-evidence"
	// BasisConcreteFixVersion - a Debian fixed version bounded the range.
	BasisConcreteFixVersion Basis = "concrete-fix-version"
	// BasisNotAffected - a Debian not-affected decision.
	BasisNotAffected Basis = "not-affected"
	// BasisDebianUnfixed - a version-less Debian action (no-dsa / unfixed / end-of-life).
	BasisDebianUnfixed Basis = "debian-unfixed"
	// BasisUpstreamUnfixed - an upstream affected signal with no bounding fix.
	BasisUpstreamUnfixed Basis = "upstream-unfixed"
	// BasisUpstreamDerived - an upstream version range bounded the range.
	BasisUpstreamDerived Basis = "upstream-derived"
	// BasisNoAuthority - no authority yielded a confident call.
	BasisNoAuthority Basis = "no-authority"
)

// Result is the facts-only resolver output for one matched source package.
// It carries no status and no escalation flag.
type Result struct {
	Outcome   Outcome
	Authority Authority
	Basis     Basis
	// Range is the vulnerable interval set (only used with [OutcomeVersionRange]).
	Range *vers.Range
	// CompareVersion is the version to test against Range, in Range.Scheme
	// (only used with [OutcomeVersionRange]). Compare directly; do not re-derive.
	// Deb ranges use the shipped version; generic ranges need the bare upstream
	// version, since a deb string can misparse at boundaries.
	CompareVersion string
	// Provenance is the build lineage, retained as context.
	Provenance pkgbuild.Provenance
	// Why is a short human-readable explanation of the decision.
	Why string
}

// BuildAnalyzer resolves the per-build analysis for a shipped source package version.
type BuildAnalyzer interface {
	Analyze(ctx context.Context, pkgName, version string) (pkgbuild.Analysis, error)
}

// Resolver selects the authority and builds the vulnerable range.
type Resolver struct {
	builds   BuildAnalyzer
	verdicts DebianVerdicts
}

// NewResolver constructs a [Resolver] over its injected lookups.
func NewResolver(builds BuildAnalyzer, verdicts DebianVerdicts) *Resolver {
	return &Resolver{builds: builds, verdicts: verdicts}
}

// Request is the per-matched-source-package resolver input.
type Request struct {
	// CVEID is the CVE under assessment e.g. "CVE-2024-1234".
	CVEID string
	// SourcePURL is the canonical identity PURL of the matched source package.
	SourcePURL string
	// ShippedVersion is the Debian package-version form of the shipped source package.
	ShippedVersion string
	// CVE is the full CVE record, read for upstream version signals.
	CVE *cve_v5.CVEV5
}

// Resolve selects the authority and returns the facts-only [Result].
func (r *Resolver) Resolve(ctx context.Context, req Request) (Result, error) {
	name, err := purl.NameOf(req.SourcePURL)
	if err != nil {
		return Result{}, fmt.Errorf("extracting source name from PURL %q: %w", req.SourcePURL, err)
	}

	analysis, err := r.builds.Analyze(ctx, name, req.ShippedVersion)
	if err != nil {
		return Result{}, fmt.Errorf("analyzing pkg-build %s@%s: %w", name, req.ShippedVersion, err)
	}

	// Fix-evidence wins regardless of provenance.
	if fixedByBuild(analysis, req.CVEID) {
		return Result{
			Outcome:    OutcomeFixed,
			Authority:  AuthorityPkgBuild,
			Basis:      BasisFixEvidence,
			Provenance: analysis.Provenance,
			Why:        fmt.Sprintf("CVE-named patch for %s applied in the %s build", req.CVEID, req.ShippedVersion),
		}, nil
	}

	// An unreadable lineage means no authority can be trusted.
	if analysis.Provenance == pkgbuild.ProvenanceUnknown {
		return undecided(analysis, "build lineage is unknown; no authority can be trusted"), nil
	}

	result, debianErr := r.resolveDebianCase(req, analysis)
	switch {
	case errors.Is(debianErr, errDebianUndecided):
		// Upstream authority is deferred; escalate instead of guessing.
		return undecided(analysis, "no usable Debian verdict; upstream authority deferred, escalating"), nil
	case debianErr != nil:
		return Result{}, debianErr
	}

	return result, nil
}

// fixedByBuild reports whether the build's fix-evidence records the CVE as fixed.
func fixedByBuild(a pkgbuild.Analysis, cveID string) bool {
	for _, fixed := range a.FixedCVEs {
		if fixed.ID == cveID {
			return true
		}
	}

	return false
}

// undecided builds the fallback result with its context.
func undecided(analysis pkgbuild.Analysis, why string) Result {
	return Result{
		Outcome:    OutcomeUndecided,
		Authority:  AuthorityNone,
		Basis:      BasisNoAuthority,
		Provenance: analysis.Provenance,
		Why:        why,
	}
}
