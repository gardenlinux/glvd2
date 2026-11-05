package glrd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/gardenlinux/glvd2/internal/config"
	"github.com/gardenlinux/glvd2/internal/whttp"
	"github.com/spf13/cobra"
)

// SBOM global release (not yet available)
// https://github.com/gardenlinux/gardenlinux/releases/download/2150.14.0/2150.14.0-a213f775.sbom
// Parameters are: Version, Version, GitCommitId.
//
//nolint:lll // long url
const sbomGlobalURLFormat = "https://github.com/gardenlinux/gardenlinux/releases/download/%s/%s-%s.sbom"

// SBOM flavor release
// https://github.com/gardenlinux/gardenlinux/releases/download/1877.25/gcp-gardener_prod-arm64-1877.25-abcdefgh.sbom
// Parameters are: Version, Flavor, Version, GitCommitId.
//
//nolint:lll // long url
const sbomURLFormat = "https://github.com/gardenlinux/gardenlinux/releases/download/%s/%s-%s-%s.sbom"

type Git struct {
	Commit      string `json:"commit"`
	CommitShort string `json:"commit_short"`
}

type GitHub struct {
	Release string `json:"release"`
}

type Version struct {
	Major int `json:"major"`
	Minor int `json:"minor"`
	Patch int `json:"patch"`
}

type LifecycleDate struct {
	Isodate   string `json:"isodate"`
	Timestamp int64  `json:"timestamp"`
}

type LifeCycle struct {
	Released LifecycleDate `json:"released"`
	EOL      LifecycleDate `json:"eol"`
}

type Attributes struct {
	SourceRepo bool `json:"source_repo"`
}

type Release struct {
	Type       string     `json:"type"`
	Version    Version    `json:"version"`
	LifeCycle  LifeCycle  `json:"lifecycle"`
	Name       string     `json:"name"`
	Git        Git        `json:"git"`
	GitHub     GitHub     `json:"github"`
	Flavors    []string   `json:"flavors"`
	Attributes Attributes `json:"attributes"`
}

type Releases struct {
	Releases []Release `json:"releases"`
}

func GetReleases(ctx context.Context, releasesURL string) ([]Release, error) {
	client := whttp.NewClient()
	releases, _, err := whttp.GetJSON[Releases](ctx, client, releasesURL)
	if err != nil {
		return nil, fmt.Errorf("retrieving releases from %q: %w", releasesURL, err)
	}

	return releases.Releases, nil
}

// GetMaintainedReleases fetches all releases and returns only those still maintained.
func GetMaintainedReleases(ctx context.Context, releasesURL string) ([]Release, error) {
	releases, err := GetReleases(ctx, releasesURL)
	if err != nil {
		return nil, err
	}

	return ReleasesMaintainedAt(releases, time.Now()), nil
}

func GetRelease(ctx context.Context, releasesURL string, reqRelease GardenLinuxRelease) (Release, error) {
	var releases []Release
	var err error

	releases, err = GetReleases(ctx, releasesURL)
	if err != nil {
		return Release{}, err
	}

	for _, release := range releases {
		if reqRelease == ReleaseSuite(release) {
			return release, nil
		}
	}

	return Release{}, errors.New("release not found")
}

// ReleasesMaintainedAt returns the releases still maintained at the given time.
func ReleasesMaintainedAt(releases []Release, now time.Time) []Release {
	maintained := make([]Release, 0, len(releases))
	for _, r := range releases {
		if r.IsMaintainedAt(now) {
			maintained = append(maintained, r)
		}
	}

	return maintained
}

// IsMaintainedAt reports whether the release is still supported at the given time.
// A release with no EOL date set is treated as maintained.
func (r Release) IsMaintainedAt(now time.Time) bool {
	if r.LifeCycle.EOL.Timestamp == 0 {
		return true
	}

	return now.Before(time.Unix(r.LifeCycle.EOL.Timestamp, 0))
}

// LocateSBOM returns the CycloneDX SBOM location for a flavor of this release.
func (r Release) LocateSBOM(flavor string) (*url.URL, error) {
	return BuildSbomURLFromRelease(MakeGardenLinuxRelease(r.Version), flavor, r.Git.CommitShort)
}

// Global release sbom url, over all flavors
//
//nolint:godoclint // line comment
func BuildGlobalSbomURLFromRelease(release GardenLinuxRelease, gitCommitId string) (*url.URL, error) {
	return url.Parse(fmt.Sprintf(sbomGlobalURLFormat, release.Format(), release.Format(), gitCommitId))
}

// Flavor release sbom url
//
//nolint:godoclint // line comment
func BuildSbomURLFromRelease(release GardenLinuxRelease, flavor, gitCommitId string) (*url.URL, error) {
	return url.Parse(fmt.Sprintf(sbomURLFormat, release.Format(), flavor, release.Format(), gitCommitId))
}

func doReleasesCmd(ctx context.Context, releasesURL string) error {
	glrdReleases, err := GetReleases(ctx, releasesURL)
	if err != nil {
		return err
	}

	for _, release := range glrdReleases {
		slog.Info("release",
			slog.String("name", release.Name),
			slog.String("github_release", release.GitHub.Release))
	}
	return nil
}

func Cmd(cfg *config.AppConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "releases",
		Short:   "Gets all Gardenlinux releases",
		Args:    cobra.NoArgs,
		GroupID: "debug",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return doReleasesCmd(cmd.Context(), cfg.GLRDReleasesURL)
		},
	}

	return cmd
}
