package repos

import (
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"

	"github.com/gardenlinux/glvd2/internal/github"
	"github.com/gardenlinux/glvd2/internal/whttp"
	"github.com/spf13/cobra"
)

type Repository struct {
	Id       int    `json:"id"`
	Name     string `json:"name"`
	FullName string `json:"full_name"`
}

type Branch struct {
	Name string `json:"name"`
}

var branchNamingRegexp = regexp.MustCompile(`^rel-\d{4,5}$`)

const (
	pageSize  int = 100 // Allowed page size for multipage api calls
	firstPage int = 1
)

func GetPackageRepoBranches(repository string) ([]Branch, error) {
	var err error

	var client *whttp.HTTPClient

	client, err = github.NewClient()
	if err != nil {
		return nil, err
	}

	var allBranches []Branch
	var url string
	var response whttp.Response

	url = fmt.Sprintf("https://api.github.com/repos/%s/%s/branches?page=%d&per_page=%d",
		"gardenlinux",
		repository,
		firstPage,
		pageSize)

	for {
		var tmpBranches []Branch
		_, response, err = client.GetJSON(url, &tmpBranches)
		if err != nil {
			slog.Error("branch download failed", "error", err)
			break
		}
		allBranches = append(allBranches, tmpBranches...)

		url = response.LinkHeader.Next
		if url == "" {
			break
		}
	}

	// Filter only branches with a name pattern
	var filteredBranches []Branch
	for _, branch := range allBranches {
		if IsRelevantBranch(branch) {
			filteredBranches = append(filteredBranches, branch)
		}
	}

	return filteredBranches, nil
}

func IsRelevantBranch(branch Branch) bool {
	return branch.Name == "main" || branch.Name == "master" || branchNamingRegexp.MatchString(branch.Name)
}

func GetPackageRepos() ([]Repository, error) {
	var err error

	var client *whttp.HTTPClient

	client, err = github.NewClient()
	if err != nil {
		return nil, err
	}

	var allRepository []Repository
	var url string
	var response whttp.Response

	url = fmt.Sprintf("https://api.github.com/orgs/%s/repos?type=public&page=%d&per_page=%d",
		"gardenlinux",
		firstPage,
		pageSize)

	for {
		var tmpRepos []Repository

		_, response, err = client.GetJSON(url, &tmpRepos)
		if err != nil {
			slog.Error("repo download failed", "error", err)
			break
		}
		allRepository = append(allRepository, tmpRepos...)

		url = response.LinkHeader.Next
		if url == "" {
			break
		}
	}

	// Filter only package-*
	var filteredRepositories []Repository
	for _, repo := range allRepository {
		if (strings.HasPrefix(repo.Name, "bp-") || strings.HasPrefix(repo.Name, "package-")) &&
			repo.Name != "package-build" {
			filteredRepositories = append(filteredRepositories, repo)
		}
	}

	return filteredRepositories, nil
}

func PackagerepoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "repos",
		Short:   "Print repos",
		GroupID: "debug", //nolint:goconst // just for debug output
		Args:    cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			repos, err := GetPackageRepos()
			if err != nil {
				return err
			}

			stdOutLogger := slog.New(slog.NewTextHandler(os.Stdout, nil))

			for _, repo := range repos {
				stdOutLogger.Info("package repo", "repo", repo)
			}
			return nil
		},
	}

	return cmd
}

func BranchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "branches",
		Short:   "Print repo's branches",
		GroupID: "debug",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, _ []string) error {
			repository, _ := cmd.Flags().GetString("repository")
			branches, err := GetPackageRepoBranches(repository)
			if err != nil {
				return err
			}

			stdOutLogger := slog.New(slog.NewTextHandler(os.Stdout, nil))

			for _, branch := range branches {
				stdOutLogger.Info("repo branches", "repo", repository, "branch", branch.Name)
			}
			return nil
		},
	}

	cmd.Flags().String("repository", "", "name of the repository")
	// MarkFlagRequired only errors when the flag is unregistered, which cannot happen here.
	_ = cmd.MarkFlagRequired("repository")

	return cmd
}
