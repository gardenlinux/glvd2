package assessment

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/gardenlinux/glvd2/internal/config"
)

const (
	dirPermissions  = 0o755
	filePermissions = 0o644
)

// ErrRecordNotFound is returned when a CVE assessment record does not exist.
var ErrRecordNotFound = errors.New("cve assessment record not found")

// Store manages reading and writing CVE assessment records as JSON files.
// It follows the CVEListV5 bucketing scheme: {base}/{year}/{bucket}xxx/{cveID}.json.
type Store struct {
	baseDir string
}

// NewStore creates a new Store that stores assessment [Record]s under the configured CVE data directory.
// It follows the CVEListV5 bucketing scheme: {base}/{year}/{bucket}xxx/{cveID}.json.
func NewStore(cfg *config.AppConfig) *Store {
	return &Store{baseDir: cfg.AssessmentDataDir}
}

// Get retrieves a CVE assessment record by its ID.
// Returns ErrNotFound if there is no record.
func (s *Store) Get(cveID string) (Record, error) {
	if !cveIDPattern.MatchString(cveID) {
		return Record{}, fmt.Errorf("invalid CVE ID: %q", cveID)
	}

	p, err := Path(s.baseDir, cveID)
	if err != nil {
		return Record{}, fmt.Errorf("resolving path for %s: %w", cveID, err)
	}

	data, err := os.ReadFile(p) //nolint:gosec // path is derived from a validated CVE ID
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Record{}, fmt.Errorf("%s: %w", cveID, ErrRecordNotFound)
		}
		return Record{}, fmt.Errorf("reading %s: %w", cveID, err)
	}

	var a Record
	if unmarshalErr := json.Unmarshal(data, &a); unmarshalErr != nil {
		return Record{}, fmt.Errorf("parsing %s: %w", cveID, unmarshalErr)
	}

	return a, nil
}

// Save writes a CVE assessment record to disk, creating directories as needed.
func (s *Store) Save(a Record) error {
	p, err := Path(s.baseDir, a.ID)
	if err != nil {
		return fmt.Errorf("resolving path for %s: %w", a.ID, err)
	}

	if mkdirErr := os.MkdirAll(filepath.Dir(p), dirPermissions); mkdirErr != nil {
		return fmt.Errorf("creating directories for %s: %w", a.ID, mkdirErr)
	}

	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling %s: %w", a.ID, err)
	}

	data = append(data, '\n')

	if writeErr := os.WriteFile(p, data, filePermissions); writeErr != nil {
		return fmt.Errorf("writing %s: %w", a.ID, writeErr)
	}

	return nil
}
