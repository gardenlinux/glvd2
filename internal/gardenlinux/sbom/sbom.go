// Package sbom provides the shared SBOM feed used by the package inventory
// and the vendored-dependency inclusion resolver.
package sbom

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/glrd"
)

// LocatorFunc resolves the SBOM URL for a release flavor.
// It returns glrd.ErrNoSBOM when no SBOM exists for the flavor.
type LocatorFunc func(release glrd.Release, flavor string) (*url.URL, error)

// FetchFunc fetches and decodes an SBOM into its CycloneDX BOM struct.
type FetchFunc func(ctx context.Context, sbomURL *url.URL) (*cdx.BOM, error)

// ReleaseSource provides the maintained Garden Linux releases for the feed.
type ReleaseSource func(ctx context.Context) ([]glrd.Release, error)

// Consumer receives via [Feed] either [AddSBOM] or [MissingSBOMSet] for each release-flavor.
type Consumer interface {
	// AddSBOM folds one release-flavor SBOM into the consumer.
	AddSBOM(bom *cdx.BOM) error
	// MissingSBOMSet reports a maintained release that lacks a complete SBOM set.
	// The consumer then decides how to react to this.
	MissingSBOMSet(ctx context.Context, release glrd.Release) error
}

// Feed lists the maintained releases once and for each release, resolves whether every
// flavor has an SBOM. When the set is complete it fetches each flavor's SBOM, delivers
// the parsed form to every consumer, and discards it before the next fetch.
// When the SBOM set is incomplete it calls every consumer with MissingSBOMSet.
func Feed(
	ctx context.Context,
	releaseSource ReleaseSource,
	locate LocatorFunc,
	fetch FetchFunc,
	consumers ...Consumer,
) error {
	releases, err := releaseSource(ctx)
	if err != nil {
		return fmt.Errorf("listing releases: %w", err)
	}

	for _, release := range releases {
		sbomURLs, complete, locErr := locateFlavors(release, locate)
		if locErr != nil {
			return locErr
		}

		if !complete {
			if missingErr := notifyMissingSBOMSet(ctx, release, consumers); missingErr != nil {
				return missingErr
			}

			continue
		}

		if fetchErr := feedRelease(ctx, release, sbomURLs, fetch, consumers); fetchErr != nil {
			return fetchErr
		}
	}

	return nil
}

// locateFlavors resolves the SBOM URL for every flavor of the release. complete
// is false when any flavor lacks an SBOM (or the release has no flavors); in
// that case nothing is fetched. It resolves URLs only - it never downloads a
// body - so completeness is known before any fetch and without holding anything.
func locateFlavors(release glrd.Release, locate LocatorFunc) ([]*url.URL, bool, error) {
	sbomURLs := make([]*url.URL, 0, len(release.Flavors))

	for _, flavor := range release.Flavors {
		sbomURL, err := locate(release, flavor)
		if errors.Is(err, glrd.ErrNoSBOM) {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, fmt.Errorf("resolving SBOM URL for flavor %q: %w", flavor, err)
		}

		sbomURLs = append(sbomURLs, sbomURL)
	}

	complete := len(release.Flavors) > 0 // no flavors means no SBOMs

	return sbomURLs, complete, nil
}

// feedRelease fetches each flavor's SBOM once, delivers the parsed form to every
// consumer, and discards it before moving to the next flavor.
func feedRelease(
	ctx context.Context,
	release glrd.Release,
	sbomURLs []*url.URL,
	fetch FetchFunc,
	consumers []Consumer,
) error {
	for _, sbomURL := range sbomURLs {
		bom, err := fetch(ctx, sbomURL)
		if err != nil {
			return fmt.Errorf("fetching SBOM: %w", err)
		}

		for _, p := range consumers {
			if addErr := p.AddSBOM(bom); addErr != nil {
				return fmt.Errorf("release %s: %w", release.Name, addErr)
			}
		}
	}

	return nil
}

// notifyMissingSBOMSet reports the incomplete release to every consumer.
func notifyMissingSBOMSet(ctx context.Context, release glrd.Release, consumers []Consumer) error {
	for _, p := range consumers {
		if err := p.MissingSBOMSet(ctx, release); err != nil {
			return fmt.Errorf("release %s: %w", release.Name, err)
		}
	}

	return nil
}
