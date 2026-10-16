package releasestatus

import (
	"context"
	"fmt"

	"github.com/gardenlinux/glvd2/internal/affectedness"
	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/gardenlinux/glvd2/internal/model/cve_v5"
	"github.com/gardenlinux/glvd2/internal/purl"
)

// Resolver resolves the facts-only affectedness of one (CVE, source package, shipped version).
type Resolver interface {
	Resolve(ctx context.Context, req affectedness.Request) (affectedness.Result, error)
}

// ShippedIndex returns the shipped source package versions per maintained release.
type ShippedIndex interface {
	// Releases returns the maintained release keys to assess.
	Releases() []string
	// Lookup returns the shipped versioned source PURL for a source package in a release,
	// or shipped=false when the release ships no such source package.
	Lookup(releaseKey, canonicalSourcePURL string) (versionedPURL string, shipped bool, err error)
}

// Service assembles the per-CVE assessor inputs and calls the pure [Assess].
type Service struct {
	resolver Resolver
	index    ShippedIndex
}

// NewService constructs an assessor service from its already-built inputs.
func NewService(resolver Resolver, index ShippedIndex) *Service {
	return &Service{resolver: resolver, index: index}
}

// Assess computes the per-release decisions for a relevant CVE record.
// cve carries the upstream signals the resolver reads and is threaded through unchanged.
func (s *Service) Assess(
	ctx context.Context,
	rec assessment.Record,
	cve *cve_v5.CVEV5,
) (map[string]assessment.ReleaseDecision, error) {
	in := Input{
		Vendored: rec.Screening.AutoTriage.Reason == assessment.TriageReasonAffectsVendoredDependency,
	}

	for _, release := range s.index.Releases() {
		rel := ReleaseInput{Release: release}
		for _, sourcePURL := range rec.Screening.Matched {
			pkg, shipped, err := s.resolvePackage(ctx, rec, cve, in.Vendored, release, sourcePURL)
			if err != nil {
				return nil, err
			}
			if !shipped {
				continue
			}
			rel.Packages = append(rel.Packages, pkg)
		}
		in.Releases = append(in.Releases, rel)
	}

	return Assess(in), nil
}

// resolvePackage looks up the shipped version of a matched source package in a release
// and for deb-path matches it resolves its affectedness. The index only reports sources
// shipped in a release, so a non-shipped or typo'd source never reaches the resolver.
func (s *Service) resolvePackage(
	ctx context.Context,
	rec assessment.Record,
	cve *cve_v5.CVEV5,
	vendored bool,
	release, sourcePURL string,
) (PackageInput, bool, error) {
	versioned, shipped, err := s.index.Lookup(release, sourcePURL)
	if err != nil {
		return PackageInput{}, false, fmt.Errorf("looking up shipped version of %s in %s: %w", sourcePURL, release, err)
	}
	if !shipped {
		return PackageInput{}, false, nil
	}

	shippedVersion, err := purl.VersionOf(versioned)
	if err != nil {
		return PackageInput{}, false, fmt.Errorf("extracting shipped version from %q: %w", versioned, err)
	}

	pkg := PackageInput{SourcePURL: sourcePURL, ShippedVersion: shippedVersion}

	// Vendored matches escalate without a deb-path resolve while component analysis is deferred.
	if vendored {
		return pkg, true, nil
	}

	result, err := s.resolver.Resolve(ctx, affectedness.Request{
		CVEID:          rec.ID,
		SourcePURL:     sourcePURL,
		ShippedVersion: shippedVersion,
		CVE:            cve,
	})
	if err != nil {
		return PackageInput{}, false, fmt.Errorf(
			"resolving affectedness of %s@%s for %s: %w", sourcePURL, shippedVersion, rec.ID, err,
		)
	}
	pkg.Affectedness = result

	return pkg, true, nil
}
