package glrd

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/gardenlinux/glvd2/internal/whttp"
	"github.com/spf13/cobra"
)

const glrdReleasesMinorURL = "https://gardenlinux-glrd.s3.eu-central-1.amazonaws.com/releases-minor.json"

type Git struct {
	Commit      string `json:"commit"`
	CommitShort string `json:"commit_short"` //nolint:tagliatelle // json field is defined with underscore
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
	Eol      LifecycleDate `json:"eol"`
}

type Attributes struct {
	SourceRepo bool `json:"source_repo"` //nolint:tagliatelle // json field is defined with underscore
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

func GetReleases() ([]Release, error) {
	client := whttp.NewClient()
	response, httpStatus, err := client.Get(glrdReleasesMinorURL)
	if err != nil {
		slog.With("url", glrdReleasesMinorURL).Error("Could not retrieve minor releases")
	}
	if httpStatus >= 400 {
		return nil, fmt.Errorf("HTTP Status error: %d", httpStatus)
	}

	var releases Releases

	err = json.Unmarshal(*response, &releases)
	if err != nil {
		slog.With("client", "glrd", "url", glrdReleasesMinorURL, "error", err).Error("Could not unmarshal json")
		return nil, err
	}

	return releases.Releases, nil
}

func doReleasesCmd() error {
	glrdReleases, err := GetReleases()
	if err != nil {
		return err
	}

	for _, release := range glrdReleases {
		//nolint:revive,forbidigo,nolintlint // just print for command
		fmt.Printf("%s - %s\n", release.Name, release.GitHub.Release)
	}
	return nil
}

func Cmd() (*cobra.Command, error) {
	cmd := &cobra.Command{
		Use:     "releases",
		Short:   "Gets GL all releases or a specific version",
		Args:    cobra.NoArgs,
		GroupID: "debug",
		RunE: func(_ *cobra.Command, _ []string) error {
			return doReleasesCmd()
		},
	}
	cmd.Flags().String("version", "", "specific version")
	err := cmd.MarkFlagRequired("version")
	if err != nil {
		slog.With("err", err).Error("could not set version flag to required")
		return nil, err
	}
	return cmd, nil
}
