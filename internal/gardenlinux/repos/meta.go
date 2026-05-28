package repos

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/gardenlinux/glvd2/internal/github"
	"github.com/gardenlinux/glvd2/internal/whttp"
	"github.com/spf13/cobra"
)

type RepositoryMetadata struct {
	Repository string // Which Repository
	Branch     string // Which Branch
	CommitId   string // State of the information

	DebianSrc       bool // Loads debian directory from a different src
	AptSrc          bool // Loads src from GL/debian package
	SalsaSrc        bool // Loads debian src from salta git repository
	UpstreamSrc     bool // Loads src from upstream project (can be archive or git repo)
	UpstreamPatches bool // applys upstream_patches via import_upstream_patches
	DebianPatches   bool // applys patches for debian, when apply_patches with directory "debian"
	GlPatches       bool // applys custom patches, usually via apply_patches
}

type FileContent struct {
	Type     string `json:"type"`
	Encoding string `json:"encoding"`
	Name     string `json:"name"`
	Content  string `json:"content"`
}

type Commit struct {
	Sha string `json:"sha"`
}

func getLatestCommitId(repoName string, branch string) (Commit, error) {
	var err error
	var client *whttp.HTTPClient

	client, err = github.NewClient()
	if err != nil {
		return Commit{}, err
	}

	var result []Commit
	_, _, err = client.GetJSON(
		fmt.Sprintf(
			"https://api.github.com/repos/gardenlinux/%s/commits?sha=%s&per_page=%d&page=%d",
			repoName,
			branch,
			1,
			1), &result)
	if err != nil {
		return Commit{}, err
	}

	if len(result) != 1 {
		slog.Error("Did not recieve the latest commit.", "commits", len(result), "repoName", repoName, "branch", branch)
		return Commit{}, fmt.Errorf("Recieved more than the latest commit or no commit at all.")
	}

	return result[0], nil
}

func getFile(repoName string, filePath string, branch string) (FileContent, error) {
	var err error
	var client *whttp.HTTPClient
	client, err = github.NewClient()
	if err != nil {
		return FileContent{}, err
	}

	var fileContent FileContent
	_, _, err = client.GetJSON(
		fmt.Sprintf(
			"https://api.github.com/repos/gardenlinux/%s/contents/%s?ref=%s",
			repoName,
			filePath,
			branch),
		&fileContent)
	if err != nil {
		return FileContent{}, err
	}

	return fileContent, nil
}

func GetPackageMeta(repoName string, branch string) (*RepositoryMetadata, error) {
	var err error
	var prepareSource FileContent
	prepareSource, err = getFile(repoName, "prepare_source", branch)
	if err != nil {
		return &RepositoryMetadata{}, err
	}

	var metadata *RepositoryMetadata
	metadata = &RepositoryMetadata{Repository: repoName, Branch: branch}

	var content string

	// Analyse prepare_source
	content, err = getFileSrc(prepareSource)
	if err != nil {
		return &RepositoryMetadata{}, err
	}
	metadata, err = AnalyzePrepareSource(content, metadata)
	if err != nil {
		return &RepositoryMetadata{}, err
	}
	metadata.Repository = repoName
	metadata.Branch = branch

	// Get CommitId for caching
	var commitId Commit
	commitId, err = getLatestCommitId(repoName, branch)
	if err != nil {
		return &RepositoryMetadata{}, err
	}
	metadata.CommitId = commitId.Sha

	return metadata, nil
}

// Remove comments, join splitted multi-lines.
func prepareContent(content string) (string, error) {
	var err error
	var buffer strings.Builder
	var result []string

	lines := strings.SplitSeq(content, "\n")
	for line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}

		// Cojoin multiline strings for eacher parsing
		trimmed, found := strings.CutSuffix(line, "\\")
		if found {
			_, err = buffer.WriteString(strings.TrimRight(trimmed, "\\"))
			if err != nil {
				return "", err
			}
		} else {
			// only continue with valid lines
			_, err = buffer.WriteString(line)
			if err != nil {
				return "", err
			}
			result = append(result, strings.TrimSpace(buffer.String()))
			buffer.Reset()
		}
	}

	if buffer.Len() > 0 {
		result = append(result, strings.TrimSpace(buffer.String()))
	}

	return strings.Join(result, "\n"), nil
}

func getFileSrc(content FileContent) (string, error) {
	var data []byte
	var err error

	slog.Debug("analyzePrepareSource")
	if content.Type != "file" {
		return "", fmt.Errorf("requested file is not a file: %s", content.Name)
	}

	switch content.Encoding {
	case "base64":
		data, err = base64.StdEncoding.DecodeString(content.Content)
		if err != nil {
			return "", err
		}
		return string(data), nil
	default:
		return "", fmt.Errorf("unknown content type: %s", content.Type)
	}
}

func ExtractPackageName(branch string) string {
	branch = strings.Replace(branch, "bp-", "", 1)
	branch = strings.Replace(branch, "package-", "", 1)
	return strings.TrimSpace(branch)
}

func AnalyzePrepareSource(content string, metadata *RepositoryMetadata) (*RepositoryMetadata, error) {
	preparedContent, err := prepareContent(content)
	if err != nil {
		return nil, err
	}
	return analyzePrepareSource(preparedContent, metadata)
}

func analyzePrepareSource(content string, metadata *RepositoryMetadata) (*RepositoryMetadata, error) {
	if metadata == nil {
		return nil, errors.New("no active metadata object")
	}

	pkgName := ExtractPackageName(metadata.Branch)

	for line := range strings.Lines(content) {
		// apt_src
		if strings.Contains(line, "apt_src") {
			metadata.AptSrc = true
			continue
		}

		// apply_patches
		if strings.Contains(line, "apply_patches") {
			if strings.Contains(line, "debian") {
				metadata.DebianPatches = true
			} else {
				metadata.GlPatches = true
			}
			continue
		}

		// import_upstream_patches
		if strings.Contains(line, "import_upstream_patches") {
			metadata.UpstreamPatches = true
			continue
		}

		if strings.Contains(line, "git clone") ||
			strings.Contains(line, "git_src") ||
			strings.Contains(line, "curl") ||
			strings.Contains(line, "wget") {
			if (len(pkgName) > 0 && (strings.Contains(line, pkgName))) || strings.Contains(line, "github.com") {
				metadata.UpstreamSrc = true
			}

			if strings.Contains(line, "salsa.debian.org") {
				metadata.SalsaSrc = true
			}
			continue
		}
	}
	return metadata, nil
}

func GetRepoPackageMetadata(repoName string, branchName string) ([]*RepositoryMetadata, error) {
	var repositories []Repository
	var err error
	var result []*RepositoryMetadata

	// if no repository is given, check all repositories
	if repoName == "" {
		repositories, err = GetPackageRepos()
		if err != nil {
			return nil, err
		}
	} else {
		repositories = append(repositories, Repository{Name: repoName})
	}

	for _, repo := range repositories {
		var branches []Branch
		// Check if all (filtered) branches or just the given,
		if repoName == "" { // means all repos requested
			// when no specific repo is given, we have to get all branches
			branches, err = GetPackageRepoBranches(repo.Name)
			if err != nil {
				return nil, err
			}
		} else {
			// when a specific repo is requested, we can specify a specific branch or all branches
			if branchName == "" {
				branches, err = GetPackageRepoBranches(repo.Name)
				if err != nil {
					return nil, err
				}
			} else {
				branches = append(branches, Branch{Name: branchName})
			}
		}

		for _, br := range branches {
			var meta *RepositoryMetadata
			meta, err = GetPackageMeta(repo.Name, br.Name)
			if err != nil {
				slog.Error(err.Error(), "repo", repo.Name, "branch", br.Name)
				continue
			}
			result = append(result, meta)
		}
	}
	return result, nil
}

func MetaCmd() (*cobra.Command, error) {
	cmd := &cobra.Command{
		Use:          "repometa",
		Short:        "Print repo metadata",
		GroupID:      "debug", //nolint:goconst // just for debug output
		SilenceUsage: false,
		Args:         cobra.OnlyValidArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var repoName string

			var branchName string
			var err error

			repoName, err = cmd.Flags().GetString("repository")
			if err != nil {
				return err
			}

			branchName, err = cmd.Flags().GetString("branch")
			if err != nil {
				return err
			}

			var metas []*RepositoryMetadata
			metas, err = GetRepoPackageMetadata(repoName, branchName)
			if err != nil {
				return err
			}

			for _, meta := range metas {
				// print metadata
				fmt.Printf("package=%s, branch=%s, commitId=%s\n", meta.Repository, meta.Branch, meta.CommitId) //nolint:forbidigo,golines,lll,revive // just for debug output
				fmt.Printf("AptSrc   : %v\n", meta.AptSrc)                                                      //nolint:forbidigo,revive // just for debug output
				fmt.Printf("DebianSrc: %v\n", meta.DebianSrc)                                                   //nolint:forbidigo,revive // just for debug output
				fmt.Printf("SalsaSrc : %v\n", meta.SalsaSrc)                                                    //nolint:forbidigo,revive // just for debug output
				fmt.Printf("UpstreamSrc : %v\n", meta.UpstreamSrc)                                              //nolint:forbidigo,revive // just for debug output
				fmt.Printf("Upstream Patches    : %v\n", meta.UpstreamPatches)                                  //nolint:forbidigo,revive // just for debug output
				fmt.Printf("Debian Patches      : %v\n", meta.DebianPatches)                                    //nolint:forbidigo,revive // just for debug output
				fmt.Printf("Gardenlinux Patches : %v\n", meta.GlPatches)                                        //nolint:forbidigo,revive // just for debug output
			}
			return nil
		},
	}
	cmd.Flags().String("branch", "", "specific branch name")
	cmd.Flags().String("repository", "", "repository name")

	return cmd, nil
}
