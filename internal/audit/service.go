// Package audit handles persisting internal analysis artifacts to disk for auditability.
package audit

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/gardenlinux/glvd2/internal/config"
)

const (
	filePermissions = 0o644
	dirPermissions  = 0o755
)

// Service handles recording audit artifacts to disk.
type Service struct {
	cfg *config.AppConfig
}

// NewService creates a new audit service.
func NewService(cfg *config.AppConfig) *Service {
	return &Service{cfg: cfg}
}

// Record persists a named audit artifact into the configured audit directory.
// The filename must include an extension like "mapping_result.json".
// Existing audit artifacts will be overwritten.
func (s *Service) Record(filename string, data any) error {
	outputDir := s.cfg.AuditDir

	if err := os.MkdirAll(outputDir, dirPermissions); err != nil {
		return fmt.Errorf("creating output directory %q: %w", outputDir, err)
	}

	path := filepath.Join(outputDir, filename)

	ext := filepath.Ext(filename)
	switch ext {
	case ".json":
		if err := writeJSON(path, data); err != nil {
			return fmt.Errorf("recording %s: %w", filename, err)
		}
	default:
		return fmt.Errorf("unsupported audit artifact format %q", ext)
	}

	slog.Info("recorded audit artifact", slog.String("path", path))
	return nil
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "    ")
	if err != nil {
		return fmt.Errorf("marshalling JSON: %w", err)
	}

	data = append(data, '\n')

	err = os.WriteFile(path, data, filePermissions)
	if err != nil {
		return fmt.Errorf("writing file: %w", err)
	}

	return nil
}
