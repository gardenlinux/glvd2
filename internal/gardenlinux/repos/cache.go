package repos

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"

	"github.com/gardenlinux/glvd2/internal/config"
)

// MetadataFlags contains only the boolean fields from RepositoryMetadata
type MetadataFlags struct {
	DebianSrc       bool `json:"debian_src"`
	AptSrc          bool `json:"apt_src"`
	SalsaSrc        bool `json:"salsa_src"`
	UpstreamSrc     bool `json:"upstream_src"`
	UpstreamPatches bool `json:"upstream_patches"`
	DebianPatches   bool `json:"debian_patches"`
	GlPatches       bool `json:"gl_patches"`
}

func buildCacheFilename(metadata *RepositoryMetadata) string {
	cfg := config.GetAppConfig()
	return path.Join(cfg.RepoMetadataCachePath, fmt.Sprintf("%s_%s.json", metadata.Repository, metadata.Branch))
}

func getFromCache(queryData *RepositoryMetadata) (*RepositoryMetadata, error) {
	var err error
	var result *RepositoryMetadata
	result = &RepositoryMetadata{}

	if len(queryData.Repository) == 0 || len(queryData.Branch) == 0 || len(queryData.CommitId) == 0 {
		return nil, errors.New("repository, branch or commitid missing")
	}

	slog.Debug("Peeking for cache", "queryData", queryData)

	// check for a caching file
	filePath := buildCacheFilename(queryData)
	_, err = os.Stat(filePath)
	if err != nil {
		return nil, err
	}

	slog.Debug("reading file", "filePath", filePath)

	var data []byte
	data, err = os.ReadFile(filePath)
	if err != nil {
		slog.Debug("could not read file", "file", filePath, "repository", queryData.Repository)
		return nil, err
	}
	err = json.Unmarshal(data, result)
	if err != nil {
		slog.Error("could not unmarshal cache file", "file", filePath, "error", err)
		return nil, err
	}
	slog.Debug("unmarshalled cache", "cache", result)

	return result, err
}

func saveToCache(metadata *RepositoryMetadata) error {
	var err error
	var data []byte
	var filePath string

	filePath = buildCacheFilename(metadata)

	// check if directory exists
	err = os.MkdirAll(filepath.Dir(filePath), 0o755) //nolint:mnd // no magic number check)
	if err != nil {
		return err
	}

	data, err = json.MarshalIndent(metadata, "", "  ") // Marshall pretty json
	err = os.WriteFile(filePath, data, 0644)
	if err != nil {
		return err
	}

	slog.Debug("persisted metadata to cache", "repository", metadata.Repository, "branch", metadata.Branch, "file", filePath)

	return nil
}
