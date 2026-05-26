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
	Repository string
	Branch     string

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

	return metadata, nil
}

// Remove comments, join splitted multi-lines.
func prepareContent(content string) string {
	var buffer strings.Builder
	var result []string

	lines := strings.SplitSeq(content, "\n")
	for line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}

		// Cojoin multiline strings for eacher parsing
		if strings.HasSuffix(line, "\\") {
			trimmed := strings.TrimSuffix(line, "\\")
			buffer.WriteString(strings.TrimRight(trimmed, "\\"))
		} else {
			// only continue with valid lines
			buffer.WriteString(line)
			result = append(result, strings.TrimSpace(buffer.String()))
			buffer.Reset()
		}
	}

	if buffer.Len() > 0 {
		result = append(result, strings.TrimSpace(buffer.String()))
	}

	return strings.Join(result, "\n")
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
	return analyzePrepareSource(prepareContent(content), metadata)
}

func analyzePrepareSource(content string, metadata *RepositoryMetadata) (*RepositoryMetadata, error) {
	if metadata == nil {
		return nil, errors.New("no active metadata object")
	}

	// fmt.Println("Content")
	// fmt.Println("-------------------------")
	// fmt.Printf("%s\n", content)
	// fmt.Println("-------------------------")

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

		if strings.Contains(line, "git clone") || strings.Contains(line, "git_src") || strings.Contains(line, "curl") || strings.Contains(line, "wget") {
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

func MetaCmd() (*cobra.Command, error) {
	cmd := &cobra.Command{
		Use:          "repometa",
		Short:        "Print repo metadata",
		GroupID:      "debug",
		SilenceUsage: false,
		Args:         cobra.OnlyValidArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var repository string
			var branch string
			var err error
			var meta *RepositoryMetadata

			repository, err = cmd.Flags().GetString("repository")
			if err != nil {
				return err
			}

			branch, err = cmd.Flags().GetString("branch")
			if err != nil {
				return err
			}

			// Check if all (filtered) branches or just the given
			var branches []Branch
			if branch == "" {
				branches, err = GetPackageRepoBranches(repository)
				if err != nil {
					return err
				}
			} else {
				branches = append(branches, Branch{Name: branch})
			}

			for _, br := range branches {
				meta, err = GetPackageMeta(repository, br.Name)
				if err != nil {
					return err
				}

				// print metadata
				fmt.Printf("package %s %s\n", meta.Repository, meta.Branch)
				fmt.Printf("DebianSrc: %v\n", meta.DebianSrc)
				fmt.Printf("AptSrc   : %v\n", meta.AptSrc)
				fmt.Printf("SalsaSrc : %v\n", meta.SalsaSrc)
				fmt.Printf("UpstreamSrc : %v\n", meta.UpstreamSrc)
				fmt.Printf("Upstream Patches    : %v\n", meta.UpstreamPatches)
				fmt.Printf("Debian Patches      : %v\n", meta.DebianPatches)
				fmt.Printf("Gardenlinux Patches : %v\n", meta.GlPatches)
			}
			return nil
		},
	}
	cmd.Flags().String("branch", "", "specific branch name")
	cmd.Flags().String("repository", "", "repository name")
	err := cmd.MarkFlagRequired("repository")
	if err != nil {
		return nil, err
	}

	return cmd, nil
}
