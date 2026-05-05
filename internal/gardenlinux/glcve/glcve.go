package glcve

import (
	"fmt"
	"log/slog"
	"regexp"

	"github.com/gardenlinux/glvd2/internal/gardenlinux/version"
	"github.com/gardenlinux/glvd2/internal/github"
	"github.com/gardenlinux/glvd2/internal/whttp"
	"github.com/spf13/cobra"
)

const (
	githubReleaseURL = "https://api.github.com/repos/gardenlinux/gardenlinux/releases/tags/%s"
	cvePatternRegex  = `CVE-\d+-\d+`
)

func getReleasePage(release version.GardenLinuxRelease) (string, error) {
	var err error
	var client *whttp.HTTPClient

	client, err = github.NewClient()
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf(githubReleaseURL, release.Name)
	var result *[]byte
	result, err = client.Get(url)
	if err != nil {
		slog.Error(
			"could not perform http request",
			slog.Any("error", err),
			slog.String("url", url))
		return "", err
	}

	return string(*result), nil
}

func ExtractMentionedCVEs(releasePage string) []string {
	re := regexp.MustCompile(cvePatternRegex)

	result := re.FindAllString(releasePage, -1)

	if result == nil {
		return []string{}
	}

	return result
}

func MentionedCVEsCmd() (*cobra.Command, error) {
	var err error
	cmd := &cobra.Command{
		Use:     "cves <version>",
		Short:   "Find CVEs mentioned in release page of <version>",
		Args:    cobra.MaximumNArgs(1),
		GroupID: "debug",
		RunE: func(cmd *cobra.Command, _ []string) error {
			version, _ := cmd.Flags().GetString("version")
			return doMentionedCVEsInRelease(version)
		},
	}
	cmd.Flags().String("version", "", "specific version")
	err = cmd.MarkFlagRequired("version")
	if err != nil {
		return nil, err
	}
	return cmd, nil
}

func GetMentionedCVEs(v string) ([]string, error) {
	vers, err := version.MakeGardenLinuxReleaseFromString(v)
	if err != nil {
		return nil, err
	}

	releasePage, err := getReleasePage(vers)
	if err != nil {
		return nil, err
	}

	mentionedCVEs := ExtractMentionedCVEs(releasePage)

	return mentionedCVEs, nil
}

func doMentionedCVEsInRelease(v string) error {
	mentionedCVEs, err := GetMentionedCVEs(v)
	if err != nil {
		return err
	}

	for _, mcve := range mentionedCVEs {
		fmt.Println(mcve) //nolint:nolintlint,revive,forbidigo // just debug output
	}

	return nil
}

func doReleasePage(v string) error {
	var err error
	var vers version.GardenLinuxRelease

	vers, err = version.MakeGardenLinuxReleaseFromString(v)
	if err != nil {
		return err
	}

	var releasePage string
	releasePage, err = getReleasePage(vers)
	if err != nil {
		return err
	}

	fmt.Printf("%s\n", releasePage) //nolint:nolintlint,revive,forbidigo // just debug output
	return nil
}

func ReleasePageCmd() (*cobra.Command, error) {
	var err error

	cmd := &cobra.Command{
		Use:     "releasepage <version>",
		Short:   "Print the release page of a <version>",
		Args:    cobra.MaximumNArgs(1),
		GroupID: "debug",
		RunE: func(cmd *cobra.Command, _ []string) error {
			var vers string
			vers, err = cmd.Flags().GetString("version")
			if err != nil {
				return err
			}
			return doReleasePage(vers)
		},
	}
	cmd.Flags().String("version", "", "specific version")
	err = cmd.MarkFlagRequired("version")
	if err != nil {
		return nil, err
	}
	return cmd, nil
}
