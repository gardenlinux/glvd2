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

func buildCacheFilename(metadata *RepositoryMetadata) string {
	cfg := config.GetAppConfig()
	return path.Join(cfg.RepoMetadataCachePath, fmt.Sprintf("%s_%s.json", metadata.Repository, metadata.Branch))
}

func getFromCache(queryData *RepositoryMetadata) (*RepositoryMetadata, error) {
	var err error
	result := &RepositoryMetadata{}

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
	data, err = os.ReadFile(filePath) //nolint:gosec // filename is derived from package and branch
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

	filePath := buildCacheFilename(metadata)

	// check if directory exists
	err = os.MkdirAll(filepath.Dir(filePath), 0o755) //nolint:mnd // no magic number check
	if err != nil {
		return err
	}

	data, err = json.MarshalIndent(metadata, "", "  ") // Marshall pretty json
	if err != nil {
		return err
	}

	err = os.WriteFile(filePath, data, 0o644) //nolint:mnd // no magic number check
	if err != nil {
		return err
	}

	slog.Debug(
		"persisted metadata to cache",
		"repository",
		metadata.Repository,
		"branch",
		metadata.Branch,
		"file",
		filePath,
	)

	return nil
}
