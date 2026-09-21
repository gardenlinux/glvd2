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

// ErrNoSBOM reports that no CycloneDX SBOM is published for a specific release flavor.
var ErrNoSBOM = errors.New("no SBOM published for release flavor")

// LocateSBOM returns the CycloneDX SBOM location for a flavor of this release.
// It returns ErrNoSBOM when no SBOM exists.
//
// TODO: not yet implemented; always reports ErrNoSBOM.
func (r Release) LocateSBOM(_ string) (*url.URL, error) {
	return nil, ErrNoSBOM
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
