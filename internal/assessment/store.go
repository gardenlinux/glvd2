package assessment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/gardenlinux/glvd2/internal/config"
)

const (
	dirPermissions  = 0o755
	filePermissions = 0o644
)

// ErrRecordNotFound is returned when a CVE assessment record does not exist.
var ErrRecordNotFound = errors.New("cve assessment record not found")

// ErrRecordIDMismatch is returned when a record file's declared ID does not match its file name.
var ErrRecordIDMismatch = errors.New("record ID does not match file name")

// Store manages reading and writing CVE assessment records as JSON files.
// It follows the CVEListV5 bucketing scheme: {base}/{year}/{bucket}xxx/{cveID}.json.
type Store struct {
	baseDir string
}

// NewStore creates a persistent assessment [Record]s [Store] under the configured directory.
// It follows the CVEListV5 bucketing scheme: {base}/{year}/{bucket}xxx/{cveID}.json.
func NewStore(cfg *config.AppConfig) *Store {
	return &Store{baseDir: cfg.AssessmentsDir}
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

// Walk visits every persisted assessment record under the store in lexical path order, calling fn for each.
func (s *Store) Walk(ctx context.Context, fn func(Record) error) error {
	seen := make(map[string]struct{})

	walkErr := filepath.WalkDir(s.baseDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walking %q: %w", path, err)
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}

		cveID := strings.TrimSuffix(d.Name(), ".json")
		if validateErr := ValidateCVEID(cveID); validateErr != nil {
			return fmt.Errorf("invalid record file name %q: %w", path, validateErr)
		}

		// Use filepath.Rel + os.OpenInRoot to enforce containment at the OS level,
		// guarding against '..' components and symlinks that point outside the store.
		relPath, relErr := filepath.Rel(s.baseDir, path)
		if relErr != nil {
			return fmt.Errorf("relativizing path %q: %w", path, relErr)
		}
		file, openErr := os.OpenInRoot(s.baseDir, relPath)
		if openErr != nil {
			return fmt.Errorf("opening %q: %w", path, openErr)
		}
		data, readErr := io.ReadAll(file)
		if closeErr := file.Close(); closeErr != nil && readErr == nil {
			readErr = fmt.Errorf("closing %q: %w", path, closeErr)
		}
		if readErr != nil {
			return fmt.Errorf("reading %q: %w", path, readErr)
		}

		var rec Record
		if unmarshalErr := json.Unmarshal(data, &rec); unmarshalErr != nil {
			return fmt.Errorf("parsing %q: %w", path, unmarshalErr)
		}
		if rec.ID != cveID {
			return fmt.Errorf("record %q declares mismatched ID %q: %w", path, rec.ID, ErrRecordIDMismatch)
		}
		if _, dup := seen[rec.ID]; dup {
			return fmt.Errorf("duplicate record for %q", rec.ID)
		}
		seen[rec.ID] = struct{}{}

		return fn(rec)
	})
	if walkErr != nil {
		return fmt.Errorf("walking assessment store %q: %w", s.baseDir, walkErr)
	}

	return nil
}
