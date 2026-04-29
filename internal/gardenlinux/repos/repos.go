package repos

import (
	"fmt"
	"strings"

	"github.com/gardenlinux/glvd2/internal/github"
	"github.com/gardenlinux/glvd2/internal/whttp"
	"github.com/spf13/cobra"
)

type Repository struct {
	Id       int    `json:"id"`
	Name     string `json:"name"`
	FullName string `json:"full_name"` //nolint:tagliatelle // json field is defined with underscore
}

func GetPackageRepos() ([]Repository, error) {
	var err error
	var httpStatus int
	var client *whttp.HTTPClient

	client, err = github.NewClient()
	if err != nil {
		return nil, err
	}

	var allRepository []Repository
	for page := range 100 {
		var pageSize = 30
		var tmpRepos []Repository
		_, httpStatus, err = client.GetJSON(fmt.Sprintf("https://api.github.com/orgs/%s/repos?&page=%d&per_page=%d", "gardenlinux", page, pageSize), &tmpRepos)
		if err != nil {
			return nil, err
		}

		allRepository = append(allRepository, tmpRepos...)

		if len(tmpRepos) < pageSize {
			break
		}
	}

	if httpStatus >= 400 {
		return nil, fmt.Errorf("HTTP Status error: %d", httpStatus)
	}

	// Filter only package-*
	var filteredRepositories []Repository
	for _, repo := range allRepository {
		fmt.Printf("Repo: %s\n", repo.Name)
		if strings.HasPrefix(repo.Name, "bp-") || strings.HasPrefix(repo.Name, "package-") {
			filteredRepositories = append(filteredRepositories, repo)
			fmt.Println("added")
		} else {
			fmt.Println("not added")
		}
	}

	fmt.Printf("%v\n", filteredRepositories)
	return filteredRepositories, nil
}

func Cmd() (*cobra.Command, error) {
	cmd := &cobra.Command{
		Use:     "repos",
		Short:   "Print repos",
		GroupID: "debug",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			repos, err := GetPackageRepos()
			if err != nil {
				return err
			}

			for _, repo := range repos {
				fmt.Printf("%s (%d) %s\n", repo.Name, repo.Id, repo.FullName) //nolint:revive,forbidigo,golines,lll // printing output for debugging
			}
			return nil
		},
	}

	return cmd, nil
}
