package glcve

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"

	"github.com/gardenlinux/glvd2/internal/gardenlinux/version"
	"github.com/gardenlinux/glvd2/internal/github"
	"github.com/gardenlinux/glvd2/internal/whttp"
	"github.com/spf13/cobra"
)

const githubReleaseURL = "https://api.github.com/repos/gardenlinux/gardenlinux/releases/tags/%s"

var cvePatternRegex = regexp.MustCompile(`CVE-\d+-\d+`)

func getReleasePage(ctx context.Context, release version.GardenLinuxRelease) (string, error) {
	var err error
	var client *whttp.HTTPClient

	client, err = github.NewClient()
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf(githubReleaseURL, release.Name)
	var result string
	result, _, err = client.GetString(ctx, url)
	if err != nil {
		slog.Error(
			"could not perform http request",
			slog.Any("error", err),
			slog.String("url", url))
		return "", err
	}

	return result, nil
}

func ExtractMentionedCVEs(releasePage string) []string {
	result := cvePatternRegex.FindAllString(releasePage, -1)

	if result == nil {
		return []string{}
	}

	return result
}

type mentionedCVEsOptions struct {
	Version string
}

func MentionedCVEsCmd() *cobra.Command {
	var opts mentionedCVEsOptions
	cmd := &cobra.Command{
		Use:     "cves <version>",
		Short:   "Find CVEs mentioned in release page of <version>",
		Args:    cobra.MaximumNArgs(1),
		GroupID: "debug",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return doMentionedCVEsInRelease(cmd.Context(), opts.Version)
		},
	}

	cmd.Flags().StringVar(&opts.Version, "version", "", "specific version")
	// MarkFlagRequired only errors when the flag is unregistered, which cannot happen here.
	_ = cmd.MarkFlagRequired("version")

	return cmd
}

func GetMentionedCVEs(ctx context.Context, v string) ([]string, error) {
	vers, err := version.MakeGardenLinuxReleaseFromString(v)
	if err != nil {
		return nil, err
	}

	releasePage, err := getReleasePage(ctx, vers)
	if err != nil {
		return nil, err
	}

	mentionedCVEs := ExtractMentionedCVEs(releasePage)

	return mentionedCVEs, nil
}

func doMentionedCVEsInRelease(ctx context.Context, v string) error {
	mentionedCVEs, err := GetMentionedCVEs(ctx, v)
	if err != nil {
		return err
	}

	for _, mcve := range mentionedCVEs {
		fmt.Println(mcve) //nolint:nolintlint,revive,forbidigo // just debug output
	}

	return nil
}

func doReleasePage(ctx context.Context, v string) error {
	var err error
	var vers version.GardenLinuxRelease

	vers, err = version.MakeGardenLinuxReleaseFromString(v)
	if err != nil {
		return err
	}

	var releasePage string
	releasePage, err = getReleasePage(ctx, vers)
	if err != nil {
		return err
	}

	fmt.Printf("%s\n", releasePage) //nolint:nolintlint,revive,forbidigo // just debug output

	return nil
}

type releasePageOptions struct {
	Version string
}

func ReleasePageCmd() *cobra.Command {
	var opts releasePageOptions
	cmd := &cobra.Command{
		Use:     "releasepage <version>",
		Short:   "Print the release page of a <version>",
		Args:    cobra.MaximumNArgs(1),
		GroupID: "debug",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return doReleasePage(cmd.Context(), opts.Version)
		},
	}

	cmd.Flags().StringVar(&opts.Version, "version", "", "specific version")
	// MarkFlagRequired only errors when the flag is unregistered, which cannot happen here.
	_ = cmd.MarkFlagRequired("version")

	return cmd
}
