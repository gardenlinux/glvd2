package glrd

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/gardenlinux/glvd2/internal/client/http"

	"github.com/spf13/cobra"
)

const GLRD_MINOR_JSON = "https://gardenlinux-glrd.s3.eu-central-1.amazonaws.com/releases-minor.json"

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
	Eol      LifecycleDate `json:"eol"`
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

func GetReleases() []Release {
	client := http.NewClient()
	response, err := client.Get(GLRD_MINOR_JSON)
	if err != nil {
		slog.With("url", GLRD_MINOR_JSON).Error("Could not retrieve minor releases")
	}

	var releases Releases

	err = json.Unmarshal(*response, &releases)
	if err != nil {
		slog.With("client", "glrd", "url", GLRD_MINOR_JSON, "error", err).Error("Could not unmarshal json")
		panic(err)
	}

	return releases.Releases
}

func doReleasesCmd() error {
	glrdReleases := GetReleases()
	for _, release := range glrdReleases {
		fmt.Printf("%s - %s\n", release.Name, release.GitHub.Release)
	}
	return nil
}

func ReleasesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "releases",
		Short: "Gets GL all releases or a specific version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return doReleasesCmd()
		},
	}
	cmd.Flags().String("version", "", "specific version")
	cmd.MarkFlagRequired("version")
	return cmd
}
