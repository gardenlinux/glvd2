package repos

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/gardenlinux/glvd2/internal/config"
	database "github.com/gardenlinux/glvd2/internal/db"
	"github.com/gardenlinux/glvd2/internal/github"
	"github.com/gardenlinux/glvd2/internal/whttp"
	"github.com/spf13/cobra"
)

type RepositoryMetadata struct {
	Repository string    `json:"repository"` // Which Repository
	Branch     string    `json:"branch"`     // Which Branch
	CommitId   string    `json:"commitid"`   // State of the information
	CreatedAt  time.Time `json:"created_at"` // Cache created at

	DebianSrc       bool `json:"debian_src"`       // Loads debian directory from a different src
	AptSrc          bool `json:"apt_src"`          // Loads src from GL/debian package
	SalsaSrc        bool `json:"salsa_src"`        // Loads debian src from salta git repository
	UpstreamSrc     bool `json:"upstream_src"`     // Loads src from upstream project (can be archive or git repo)
	UpstreamPatches bool `json:"upstream_patches"` // applys upstream_patches via import_upstream_patches
	DebianPatches   bool `json:"debian_patches"`   // applys patches for debian, when apply_patches with directory "debian"
	GlPatches       bool `json:"gl_patches"`       // applys custom patches, usually via apply_patches
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

func getLatestCommitId(repoName, branch string) (Commit, error) {
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
			1,
		), &result,
	)
	if err != nil {
		return Commit{}, err
	}

	if len(result) != 1 {
		slog.Error("did not receive the latest commit", "commits", len(result), "repoName", repoName, "branch", branch)
		return Commit{}, errors.New("received more than the latest commit or no commit at all")
	}

	return result[0], nil
}

func getFile(repoName, filePath, branch string) (FileContent, error) {
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
			branch,
		),
		&fileContent,
	)
	if err != nil {
		return FileContent{}, err
	}

	return fileContent, nil
}

func GetPackageMeta(repoName, branch string) (*RepositoryMetadata, error) {
	var err error
	var prepareSource FileContent
	var content string
	var queryData RepositoryMetadata
	var metadata *RepositoryMetadata

	queryData = RepositoryMetadata{Repository: repoName, Branch: branch}

	// Get CommitId for caching
	var commitId Commit
	commitId, err = getLatestCommitId(repoName, branch)
	if err != nil {
		return nil, err
	}
	queryData.CommitId = commitId.Sha

	// check for cache
	metadata, err = getFromCache(&queryData)
	if err != nil {
		// Cache miss, getting the file from github repo
		slog.Error("cache miss", "repository", queryData.Repository, "branch", queryData.Branch, "error", err)

		prepareSource, err = getFile(repoName, "prepare_source", branch)
		if err != nil {
			return nil, err
		}

		// Analyse prepare_source
		content, err = getFileSrc(prepareSource)
		if err != nil {
			return nil, err
		}
		metadata, err = AnalyzePrepareSource(content, queryData)
		if err != nil {
			return nil, err
		}

		// Save result as cache
		err = saveToCache(metadata)
		if err != nil {
			slog.Error("could not persist cache file", "repository", repoName, "branch", branch, "error", err)
		}
	}

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

func AnalyzePrepareSource(content string, queryData RepositoryMetadata) (*RepositoryMetadata, error) {
	preparedContent, err := prepareContent(content)
	if err != nil {
		return nil, err
	}
	return analyzePrepareSource(preparedContent, queryData)
}

func analyzePrepareSource(content string, queryData RepositoryMetadata) (*RepositoryMetadata, error) {
	var metadata RepositoryMetadata
	metadata.Repository = queryData.Repository
	metadata.Branch = queryData.Branch
	metadata.CommitId = queryData.CommitId
	metadata.CreatedAt = time.Now()

	pkgName := ExtractPackageName(queryData.Repository)

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
			if (len(pkgName) > 0 && strings.Contains(line, pkgName)) || strings.Contains(line, "github.com") {
				metadata.UpstreamSrc = true
			}

			if strings.Contains(line, "salsa.debian.org") {
				metadata.SalsaSrc = true
			}
			continue
		}
	}
	return &metadata, nil
}

func GetRepoPackageMetadata(repoName, branchName string) ([]*RepositoryMetadata, error) {
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
		// Check if all (filtered) branches or just the given. If no repo is named, we always
		// query all branches
		if repoName == "" || branchName == "" {
			branches, err = GetPackageRepoBranches(repo.Name)
			if err != nil {
				return nil, err
			}
		} else {
			branches = append(branches, Branch{Name: branchName})
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

func MetaCmd(cfg *config.AppConfig) (*cobra.Command, error) {
	cmd := &cobra.Command{
		Use:          "metadata",
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

			// Update database if necessary
			db, err := database.Regenerate(cfg.InternalSqliteDBPath)
			if err != nil {
				slog.Error("could not open database", slog.Any("error", err))
				return err
			}
			defer func() {
				if errDb := db.Close(); errDb != nil {
					slog.Error("error during closing of the database", slog.Any("error", errDb))
				}
			}()

			var metas []*RepositoryMetadata
			metas, err = GetRepoPackageMetadata(repoName, branchName)
			if err != nil {
				return err
			}

			stdOutLogger := slog.New(slog.NewTextHandler(os.Stdout, nil))

			for _, meta := range metas {
				// print metadata
				stdOutLogger.
					With("repository", meta.Repository, "branch", meta.Branch, "commitid", meta.CommitId).
					Info("analysis",
						"AptSrc", meta.AptSrc,
						"DebianSrc", meta.DebianSrc,
						"SalsaSrc", meta.SalsaSrc,
						"UpstreamSrc", meta.UpstreamSrc,
						"Upstream Patches", meta.UpstreamPatches,
						"Debian Patches", meta.DebianPatches,
						"Gardenlinux Patches", meta.GlPatches,
					)
			}
			return nil
		},
	}
	cmd.Flags().String("branch", "", "specific branch name")
	cmd.Flags().String("repository", "", "repository name")

	return cmd, nil
}
