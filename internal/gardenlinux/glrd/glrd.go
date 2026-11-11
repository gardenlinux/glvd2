package glrd

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"time"

	"github.com/gardenlinux/glvd2/internal/config"
	"github.com/gardenlinux/glvd2/internal/whttp"
	"github.com/spf13/cobra"
)

// versionPattern matches a Garden Linux version string (major.minor or major.minor.patch).
var versionPattern = regexp.MustCompile(`^\d+\.\d+(\.\d+)?$`)

// ValidateVersion checks that s is a well-formed Garden Linux version string.
func ValidateVersion(s string) error {
	if !versionPattern.MatchString(s) {
		return fmt.Errorf("invalid version %q: want major.minor or major.minor.patch", s)
	}

	return nil
}

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

	for _, r := range releases.Releases {
		if verr := ValidateVersion(r.Version.String()); verr != nil {
			return nil, fmt.Errorf("release %q from %q: %w", r.Name, releasesURL, verr)
		}
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

// semverMajorThreshold is the first major version that uses the three-part
// semver scheme (major.minor.patch). Earlier majors use two parts (major.minor).
const semverMajorThreshold = 2017

// String renders the version as its canonical Garden Linux string
// ("major.minor" for legacy releases, "major.minor.patch" for semver releases).
func (v Version) String() string {
	if v.Major >= semverMajorThreshold {
		return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	}

	return fmt.Sprintf("%d.%d", v.Major, v.Minor)
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
