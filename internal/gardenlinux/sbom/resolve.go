package sbom

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/glrd"
	"github.com/gardenlinux/glvd2/internal/whttp"
)

// sbomURLFormat addresses a flavor's CycloneDX SBOM in a Garden Linux release.
// https://github.com/gardenlinux/gardenlinux/releases/download/1877.25/gcp-gardener_prod-arm64-1877.25-abcdefgh.sbom
// Parameters are: Version, Flavor, Version, GitCommitShort.
const sbomURLFormat = "https://github.com/gardenlinux/gardenlinux/releases/download/%s/%s-%s-%s.sbom"

// ErrNoSBOM reports that no CycloneDX SBOM is published for a release flavor.
var ErrNoSBOM = errors.New("no SBOM published for release flavor")

// BuildSBOMURL derives the CycloneDX SBOM URL for a release flavor.
func BuildSBOMURL(release glrd.Release, flavor string) (*url.URL, error) {
	versionStr := release.Version.String()

	return url.Parse(fmt.Sprintf(sbomURLFormat, versionStr, flavor, versionStr, release.Git.CommitShort))
}

// LocateSBOM resolves a flavor's SBOM URL and probes its existence.
// It returns ErrNoSBOM when no SBOM is published for the flavor.
func LocateSBOM(ctx context.Context, release glrd.Release, flavor string) (*url.URL, error) {
	sbomURL, err := BuildSBOMURL(release, flavor)
	if err != nil {
		return nil, err
	}

	client := whttp.NewClient()
	status, err := client.Head(ctx, sbomURL.String())
	if err != nil {
		return nil, err
	}

	switch {
	case status == http.StatusNotFound:
		return nil, ErrNoSBOM
	case status >= http.StatusBadRequest:
		return nil, fmt.Errorf("checking SBOM at %q: unexpected HTTP status %d", sbomURL, status)
	default:
		return sbomURL, nil
	}
}

// FetchCycloneDX fetches and decodes the CycloneDX SBOM at sbomURL.
// It returns ErrNoSBOM when no SBOM exists.
func FetchCycloneDX(ctx context.Context, sbomURL *url.URL) (*cdx.BOM, error) {
	client := whttp.NewClient()
	raw, status, err := client.GetString(ctx, sbomURL.String())
	if status == http.StatusNotFound {
		return nil, ErrNoSBOM
	}
	if err != nil {
		return nil, err
	}

	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(strings.NewReader(raw), cdx.BOMFileFormatJSON)
	if err = decoder.Decode(bom); err != nil {
		return nil, err
	}

	return bom, nil
}
