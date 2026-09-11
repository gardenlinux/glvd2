package db

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/sqlite"
	_ "github.com/golang-migrate/migrate/v4/source/file" // registers the file:// migration source
	_ "modernc.org/sqlite"                               // registers the "sqlite" modernc driver
)

// modernc.org/sqlite ignores plain query params (journal_mode=..., cache=...);
// pragmas must use its _pragma syntax on a file URI.
const sqlitePragmas = "?_pragma=busy_timeout(3000)" +
	"&_pragma=journal_mode(WAL)" +
	"&_pragma=foreign_keys(true)"

// Regenerate clears the DB file, recreates the structure via migration, and returns a DB connection.
func Regenerate(fp string) (*sql.DB, error) {
	// Ensure that the directory for the db file exists.
	dbDirectory := filepath.Dir(fp)
	switch _, err := os.Stat(dbDirectory); {
	case err == nil:
		// directory already exists
	case errors.Is(err, os.ErrNotExist):
		if mkErr := os.MkdirAll(dbDirectory, 0o755); mkErr != nil { //nolint:mnd // folder permissions
			return nil, fmt.Errorf("creating database directory %s: %w", dbDirectory, mkErr)
		}
		slog.Info("Created database directory", "directory", dbDirectory)
	default:
		return nil, fmt.Errorf("checking database directory %s: %w", dbDirectory, err)
	}

	// We start each run with a fresh database.
	for _, p := range []string{fp, fp + "-wal", fp + "-shm"} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("removing %s: %w", p, err)
		}
	}

	if err := runMigrations(fp); err != nil {
		return nil, err
	}

	db, err := open(fp)
	if err != nil {
		return nil, err
	}

	return db, nil
}

// open a sqlite db from file.
func open(fp string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", "file:"+fp+sqlitePragmas)
	if err != nil {
		return nil, err
	}

	// SQLite has a single writer. Pin to one connection to serialize all access.
	db.SetMaxOpenConns(1)

	return db, nil
}

func runMigrations(fp string) error {
	db, err := open(fp)
	if err != nil {
		return err
	}

	driver, err := sqlite.WithInstance(db, &sqlite.Config{NoTxWrap: true})
	if err != nil {
		return errors.Join(fmt.Errorf("creating migrate driver: %w", err), db.Close())
	}

	m, err := migrate.NewWithDatabaseInstance("file://internal/db/migrations/", "sqlite", driver)
	if err != nil {
		return errors.Join(fmt.Errorf("creating migrator: %w", err), db.Close())
	}
	defer func() { _, _ = m.Close() }()

	if upErr := m.Up(); upErr != nil && !errors.Is(upErr, migrate.ErrNoChange) {
		return fmt.Errorf("applying migrations: %w", upErr)
	}

	return nil
}
