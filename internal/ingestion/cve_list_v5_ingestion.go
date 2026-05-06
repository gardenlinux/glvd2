package ingestion

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gardenlinux/glvd2/internal/config"
	"github.com/gardenlinux/glvd2/internal/model/cve_v5"
)

type CVEV5IngestionService struct {
	cfg *config.AppConfig
}

func NewCVEV5IngestionService(cfg *config.AppConfig) *CVEV5IngestionService {
	return &CVEV5IngestionService{
		cfg: cfg,
	}
}

func (s CVEV5IngestionService) parseJSONFile(fp string) (*cve_v5.CVEV5, error) {
	fp = filepath.Clean(fp)
	if !strings.HasPrefix(fp, filepath.Clean(s.cfg.CVEListV5SubRepoPath)) {
		slog.Error("Prefix does not match",
			slog.String("filepath", fp), slog.String("expectedPrefix", s.cfg.CVEListV5SubRepoPath))
		return nil, errors.New("unsafe file path used")
	}
	jsonFile, err := os.Open(fp)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := jsonFile.Close(); closeErr != nil {
			slog.Error("Error while closing JSON file",
				slog.Any("error", err))
		}
	}()

	bytes, err := io.ReadAll(jsonFile)
	if err != nil {
		return nil, err
	}

	var cveV5 cve_v5.CVEV5
	err = json.Unmarshal(bytes, &cveV5)
	if err != nil {
		enrichedErr := fmt.Errorf("parsing JSON file \"%s\" failed: %w", fp, err)
		return nil, enrichedErr
	}

	return &cveV5, nil
}

func (s CVEV5IngestionService) parseWorker(pathQueue <-chan string, cveCh chan<- *cve_v5.CVEV5, ec chan error) {
	for path := range pathQueue {
		cveV5, err := s.parseJSONFile(path)
		if err != nil {
			ec <- err
			return
		}

		cveCh <- cveV5
	}
}

// ReceiveCVEs parses the cves folder.
func (s CVEV5IngestionService) ReceiveCVEs() (<-chan *cve_v5.CVEV5, <-chan error) {
	cveBufferSize := 64
	ch := make(chan *cve_v5.CVEV5, cveBufferSize)
	ec := make(chan error, 1)

	go func() {
		defer close(ch)
		defer close(ec)

		pathQueueSize := 32
		pathQueue := make(chan string, pathQueueSize)
		var wg sync.WaitGroup
		for range 16 {
			wg.Go(func() {
				s.parseWorker(pathQueue, ch, ec)
			})
		}

		err := filepath.WalkDir(s.cfg.CVEListV5SubRepoPath, func(fp string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if !d.IsDir() && strings.HasPrefix(filepath.Base(fp), "CVE-") && filepath.Ext(fp) == ".json" {
				pathQueue <- fp
			}

			return nil
		})
		if err != nil {
			ec <- err
		}
		close(pathQueue)

		wg.Wait()
	}()

	return ch, ec
}
