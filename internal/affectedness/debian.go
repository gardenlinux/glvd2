package affectedness

import (
	"errors"
	"fmt"

	"github.com/gardenlinux/glvd2/internal/debsectracker"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/pkgbuild"
	"github.com/git-pkgs/vers"
)

// errDebianUndecided signals that Debian did not yield a verdict.
var errDebianUndecided = errors.New("debian did not decide")

// DebianVerdicts looks up the Debian verdict for a (CVE, source package) pair.
type DebianVerdicts interface {
	Lookup(cveID, sourcePURL string) (debsectracker.Verdict, error)
}

// resolveDebianCase consults the Debian verdict when the build lineage comes from Debian.
// It returns [errDebianUndecided] when Debian did not decide.
func (r *Resolver) resolveDebianCase(req Request, analysis pkgbuild.Analysis) (Result, error) {
	// Debian is consulted only when the lineage comes from Debian.
	if analysis.Provenance != pkgbuild.ProvenanceTakenFromTesting &&
		analysis.Provenance != pkgbuild.ProvenancePatchedFromDebian {
		return Result{}, errDebianUndecided
	}

	verdict, err := r.verdicts.Lookup(req.CVEID, req.SourcePURL)
	if err != nil {
		return Result{}, fmt.Errorf(
			"looking up Debian verdict for %s and %s: %w",
			req.SourcePURL,
			req.CVEID,
			err,
		)
	}

	switch verdict.Status() {
	case debsectracker.StatusNotAffected:
		return Result{
			Outcome:    OutcomeNotAffected,
			Authority:  AuthorityDebian,
			Basis:      BasisNotAffected,
			Provenance: analysis.Provenance,
			Why:        "Debian marks the source package not-affected",
		}, nil

	case debsectracker.StatusAffectedNoFix:
		return Result{
			Outcome:    OutcomeAffectedNoRange,
			Authority:  AuthorityDebian,
			Basis:      BasisDebianUnfixed,
			Provenance: analysis.Provenance,
			Why: fmt.Sprintf(
				"Debian marks the source package affected with no fixed version (%q).",
				verdict.Reason,
			),
		}, nil

	case debsectracker.StatusFixed:
		vulnRange := vers.LessThan(verdict.FixedVersion, false)
		vulnRange.Scheme = "deb"

		return Result{
			Outcome:        OutcomeVersionRange,
			Authority:      AuthorityDebian,
			Basis:          BasisConcreteFixVersion,
			Range:          vulnRange,
			CompareVersion: req.ShippedVersion,
			Provenance:     analysis.Provenance,
			Why:            fmt.Sprintf("Debian fixed in %s; vulnerable below it", verdict.FixedVersion),
		}, nil

	case debsectracker.StatusUndecided:
		// Falls through to Debian undecided.
	}

	return Result{}, errDebianUndecided
}
