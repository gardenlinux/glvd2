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

type Branch struct {
	Name string `json:"name"`
}

func GetPackageRepoBranches(repository string) ([]Branch, error) {
	var err error

	var client *whttp.HTTPClient

	client, err = github.NewClient()
	if err != nil {
		return nil, err
	}

	var allBranches []Branch
	for page := range 100 {
		var pageSize = 30
		var tmpBranches []Branch
		_, _, err = client.GetJSON(
			fmt.Sprintf("https://api.github.com/repos/%s/%s/branches?page=%d&per_page=%d",
				"gardenlinux",
				repository,
				page,
				pageSize),
			&tmpBranches)

		if err != nil {
			return nil, err
		}

		allBranches = append(allBranches, tmpBranches...)

		if len(tmpBranches) < pageSize {
			break
		}
	}

	// Filter only branches with a name pattern
	var filteredBranches []Branch
	for _, branch := range allBranches {
		if branch.Name == "main" || branch.Name == "master" || strings.HasPrefix(branch.Name, "rel-") {
			filteredBranches = append(filteredBranches, branch)
		}
	}

	return filteredBranches, nil
}

func GetPackageRepos() ([]Repository, error) {
	var err error

	var client *whttp.HTTPClient

	client, err = github.NewClient()
	if err != nil {
		return nil, err
	}

	var allRepository []Repository
	for page := range 100 {
		var pageSize = 30
		var tmpRepos []Repository
		_, _, err = client.GetJSON(
			fmt.Sprintf("https://api.github.com/orgs/%s/repos?&page=%d&per_page=%d",
				"gardenlinux",
				page,
				pageSize),
			&tmpRepos)
		if err != nil {
			return nil, err
		}

		allRepository = append(allRepository, tmpRepos...)

		if len(tmpRepos) < pageSize {
			break
		}
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

func ReposCmd() (*cobra.Command, error) {
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

func RepoCmd() (*cobra.Command, error) {
	cmd := &cobra.Command{
		Use:     "repo",
		Short:   "Print repo's branches",
		GroupID: "debug",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, _ []string) error {
			repository, _ := cmd.Flags().GetString("repository")
			branches, err := GetPackageRepoBranches(repository)
			if err != nil {
				return err
			}

			for _, branch := range branches {
				fmt.Printf("%s - %s\n", repository, branch.Name) //nolint:revive,forbidigo,golines,lll // printing output for debugging
			}
			return nil
		},
	}

	cmd.Flags().String("repository", "", "name of the repository")
	err := cmd.MarkFlagRequired("repository")
	if err != nil {
		return nil, err
	}

	return cmd, nil
}
