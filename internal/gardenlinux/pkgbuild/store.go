package pkgbuild

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/gardenlinux/glvd2/internal/config"
	"github.com/gardenlinux/glvd2/internal/debian"
	packageurl "github.com/package-url/packageurl-go"
)

const (
	dirPermissions  = 0o755
	filePermissions = 0o644
)

// storeFile contains one [Analysis] for each version of a package.
type storeFile struct {
	Versions map[string]Analysis `json:"versions"`
}

// Store is the committed per-package analysis store,
// which contains one JSON file for each source package name.
type Store struct {
	baseDir string
}

// NewStore creates a [Store] under the configured pkg-build store directory.
func NewStore(cfg *config.AppConfig) *Store {
	return &Store{baseDir: cfg.PkgBuildStoreDir}
}

func (s *Store) path(pkgName string) string {
	return filepath.Join(s.baseDir, pkgName+".json")
}

// Lookup returns the stored analysis for a (pkgName, shipped version)
// or ErrNotFound if no entry exists.
func (s *Store) Lookup(pkgName, version string) (Analysis, error) {
	file, err := s.load(pkgName)
	if err != nil {
		return Analysis{}, err
	}

	entry, ok := file.Versions[storeVersion(version)]
	if !ok {
		return Analysis{}, ErrNotFound
	}

	return entry, nil
}

// LookupByPURL resolves a versioned source PURL to its stored analysis.
func (s *Store) LookupByPURL(rawPURL string) (Analysis, error) {
	pkgName, version, err := splitVersionedPURL(rawPURL)
	if err != nil {
		return Analysis{}, err
	}

	return s.Lookup(pkgName, version)
}

// Save persists an analysis for a (pkgName, version). Entries are immutable:
// saving a version that already exists returns ErrAlreadyStored and leaves the
// stored entry untouched.
func (s *Store) Save(a Analysis) error {
	file, err := s.load(a.PkgName)
	if err != nil {
		return err
	}
	if file.Versions == nil {
		file.Versions = map[string]Analysis{}
	}

	key := storeVersion(a.Version)
	if _, exists := file.Versions[key]; exists {
		return fmt.Errorf("%s@%s: %w", a.PkgName, key, ErrAlreadyStored)
	}
	file.Versions[key] = a

	return s.write(a.PkgName, file)
}

// validatePkgName rejects a name that is not a well-formed Debian package name,
// which also guarantees it is a safe single path component for the store file.
func validatePkgName(pkgName string) error {
	if err := debian.ValidatePackageName(pkgName); err != nil {
		return fmt.Errorf("invalid store package name %q: %w", pkgName, err)
	}

	return nil
}

func (s *Store) load(pkgName string) (storeFile, error) {
	if err := validatePkgName(pkgName); err != nil {
		return storeFile{}, err
	}

	data, err := os.ReadFile(s.path(pkgName))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return storeFile{Versions: map[string]Analysis{}}, nil
		}
		return storeFile{}, fmt.Errorf("reading store for %s: %w", pkgName, err)
	}

	var file storeFile
	if unmarshalErr := json.Unmarshal(data, &file); unmarshalErr != nil {
		return storeFile{}, fmt.Errorf("parsing store for %s: %w", pkgName, unmarshalErr)
	}
	if file.Versions == nil {
		file.Versions = map[string]Analysis{}
	}

	return file, nil
}

func (s *Store) write(pkgName string, file storeFile) error {
	if err := validatePkgName(pkgName); err != nil {
		return err
	}

	if err := os.MkdirAll(s.baseDir, dirPermissions); err != nil {
		return fmt.Errorf("creating store dir: %w", err)
	}

	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling store for %s: %w", pkgName, err)
	}
	data = append(data, '\n')

	if writeErr := os.WriteFile(s.path(pkgName), data, filePermissions); writeErr != nil {
		return fmt.Errorf("writing store for %s: %w", pkgName, writeErr)
	}

	return nil
}

// splitVersionedPURL extracts the source name and version from a versioned PURL.
func splitVersionedPURL(rawPURL string) (string, string, error) {
	p, err := packageurl.FromString(rawPURL)
	if err != nil {
		return "", "", fmt.Errorf("parsing PURL %q: %w", rawPURL, err)
	}
	if p.Version == "" {
		return "", "", fmt.Errorf("versioned PURL %q has no version", rawPURL)
	}

	return p.Name, p.Version, nil
}
