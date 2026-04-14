package db

import (
	"database/sql"
)

// Open a sqlite db from file.
func Open() (*sql.DB, error) {
	db, err := sql.Open("sqlite",
		"data/internal.sqlite?journal_mode=WAL&busy_timeout=3000&secure_delete=true&foreign_keys=true&cache=shared")
	if err != nil {
		return nil, err
	}

	// no parallel access
	db.SetMaxOpenConns(1)

	return db, nil
}
