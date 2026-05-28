package db

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/sqlite" // blank import like lib proposes
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

const sqliteConnectionStringSuffix = "?journal_mode=WAL&busy_timeout=3000&secure_delete=true" +
	"&foreign_keys=true&cache=shared&x-no-tx-wrap=true"

// Regenerate clears the DB file, recreates the structure via migration, and returns a DB connection.
func Regenerate(fp string) (*sql.DB, error) {
	// ensure that the directory exists
	dataDirectory := filepath.Base(filepath.Dir(fp))
	if _, errstat := os.Stat(dataDirectory); os.IsNotExist(errstat) {
		errstat = os.Mkdir(dataDirectory, 0o755) //nolint:mnd // no magic number check
		if errstat != nil {
			return nil, errstat
		}
		slog.Info("Created database directory", "directory", dataDirectory)
	}
	// ensure that the file exists
	f, err := os.OpenFile(fp, os.O_CREATE, 0o644) //nolint:gosec,mnd // no user input and fil
	if err != nil {
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}

	// clear the file content
	if err = os.Truncate(fp, 0); err != nil {
		return nil, err
	}

	if err = Migrate(fp); err != nil {
		return nil, err
	}

	db, err := Open(fp)
	if err != nil {
		return nil, err
	}

	return db, nil
}

// Open a sqlite db from file.
func Open(fp string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", fp+sqliteConnectionStringSuffix)
	if err != nil {
		return nil, err
	}

	// no parallel access
	db.SetMaxOpenConns(1)

	return db, nil
}

func Migrate(fp string) error {
	m, err := migrate.New(
		"file://internal/db/migrations/",
		"sqlite://"+fp+sqliteConnectionStringSuffix)
	if err != nil {
		return err
	}

	fmt.Println("Up")
	err = m.Up()
	if err != nil {
		return err
	}

	return nil
}
