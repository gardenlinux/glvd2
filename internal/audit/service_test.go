package audit_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/gardenlinux/glvd2/internal/audit"
	"github.com/gardenlinux/glvd2/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type sampleData struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

func TestRecord_WritesJSONFiles(t *testing.T) {
	t.Parallel()

	outputDir := t.TempDir()
	cfg := &config.AppConfig{AuditDir: outputDir}
	s := audit.NewService(cfg)

	data := sampleData{Name: "test", Count: 42}

	err := s.Record("result.json", data)
	require.NoError(t, err)

	//nolint:gosec // test reading from temp dir
	raw, err := os.ReadFile(filepath.Join(outputDir, "result.json"))
	require.NoError(t, err)

	var got sampleData
	err = json.Unmarshal(raw, &got)
	require.NoError(t, err)
	assert.Equal(t, data, got)
}

func TestRecord_CreatesOutputDir(t *testing.T) {
	t.Parallel()

	outputDir := filepath.Join(t.TempDir(), "nested", "dir")
	cfg := &config.AppConfig{AuditDir: outputDir}
	s := audit.NewService(cfg)

	err := s.Record("items.json", []string{"a", "b", "c"})
	require.NoError(t, err)

	_, err = os.Stat(filepath.Join(outputDir, "items.json"))
	require.NoError(t, err)
}

func TestRecord_UnsupportedFormat(t *testing.T) {
	t.Parallel()

	outputDir := t.TempDir()
	cfg := &config.AppConfig{AuditDir: outputDir}
	s := audit.NewService(cfg)

	err := s.Record("data.xml", "some data")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported audit artifact format")
}
