package debsectracker_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/gardenlinux/glvd2/internal/config"
	"github.com/gardenlinux/glvd2/internal/ingestion/debsectracker"
	"github.com/gardenlinux/glvd2/internal/repository"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/sqlite"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

const sqliteConnectionStringSuffix = "?journal_mode=WAL&busy_timeout=3000&secure_delete=true" +
	"&foreign_keys=true&cache=shared&x-no-tx-wrap=true"

// getAllTriageEntriesWithRelationsFromDB: Fetches all entries in a simple way,
// so with the current implementation only recommended for tests with a limited amount of data.
func getAllTriageEntriesWithRelationsFromDB(
	ctx context.Context,
	queries *repository.Queries,
) ([]debsectracker.TriageEntry, error) {
	entries := []debsectracker.TriageEntry{}

	debTriages, err := queries.ListDebianTriages(ctx)
	if err != nil {
		return nil, err
	}

	for _, dt := range debTriages {
		affectedPackages, pErr := queries.ListAffectedPackagesForDebianTriage(ctx, dt.CVEID)
		if pErr != nil {
			return nil, pErr
		}

		affectedReleases, rErr := queries.ListAffectedReleasesForDebianTriage(ctx, dt.CVEID)
		if rErr != nil {
			return nil, rErr
		}

		entries = append(entries, debsectracker.TriageEntry{
			Triage:           dt,
			AffectedPackages: affectedPackages,
			AffectedReleases: affectedReleases,
		})
	}

	return entries, nil
}

func minifyJSON(i []byte) ([]byte, error) {
	var d []any

	err := json.Unmarshal(i, &d)
	if err != nil {
		return nil, err
	}

	o, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}

	return o, nil
}

type IngestTriageTestCase struct {
	name string // description of this test case
	// Named input parameters for receiver constructor.
	cfg                     *config.AppConfig
	expectedEntriesJSONPath string
	expectedError           error // nil if no error is expected
}

func genIngestTriageTestCase(name, folderName string, expectedError error) IngestTriageTestCase {
	return IngestTriageTestCase{
		name: name,
		cfg: &config.AppConfig{
			CVEListV5SubRepoPath:     "",
			DebSecTrackerSubRepoPath: "./testdata/" + folderName + "/debsectracker",
			InternalSqliteDBPath:     "",
		},
		expectedEntriesJSONPath: "./testdata/" + folderName + "/expected_entries.json",
		expectedError:           expectedError,
	}
}

func TestService_IngestTriage(t *testing.T) {
	t.Parallel()
	tests := []IngestTriageTestCase{
		genIngestTriageTestCase("valid triage entry", "validentrytest", nil),
		genIngestTriageTestCase("valid triage entry with advisory (DSA + DLA)", "validentrywithadvisorytest", nil),
		genIngestTriageTestCase("valid entry with multiple packages", "multiplepackagesentrytest", nil),
		genIngestTriageTestCase("valid TODO triage entry", "todotest", nil),
		genIngestTriageTestCase("valid triage entry with note in TODO", "todonotetest", nil),
		genIngestTriageTestCase("valid REJECTED triage entry", "rejectedtest", nil),
		genIngestTriageTestCase("valid RESERVED triage entry", "reservedtest", nil),
		genIngestTriageTestCase("valid NOT-FOR-US triage entry", "notforustest", nil),
		genIngestTriageTestCase("not disclosed (-XXXX) entry skipped", "notdisclosedskiptest", nil),
		genIngestTriageTestCase("multiple valid entries", "multipleentriestest", nil), // XXX check result
		genIngestTriageTestCase(
			"missing header line at start",
			"missingheaderlineatstarttest",
			debsectracker.ErrMissingHeaderLine,
		),
		genIngestTriageTestCase(
			"wrong header line format",
			"wrongheaderlinetest",
			debsectracker.ErrUnknownHeaderLineFormat,
		),
		genIngestTriageTestCase("unknown format", "unknownformattest", debsectracker.ErrUnknownFormat),
		genIngestTriageTestCase("empty input", "emptyinputtest", debsectracker.ErrMissingHeaderLine),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			th := "IngestTriage() - " + tt.name
			// in-memory test DB setup
			db, err := sql.Open("sqlite", ":memory:"+sqliteConnectionStringSuffix)
			if err != nil {
				t.Errorf("%s: setup failed - in-memory DB creation: %v", th, err)
				return
			}
			defer func() {
				if err = db.Close(); err != nil {
					t.Errorf("%s: clean up failed: %v", th, err)
				}
			}()
			driver, err := sqlite.WithInstance(
				db,
				&sqlite.Config{MigrationsTable: "", DatabaseName: "", NoTxWrap: true},
			)
			if err != nil {
				t.Errorf("%s: setup failed - DB driver setup for migration: %v", th, err)
				return
			}
			m, err := migrate.NewWithDatabaseInstance(
				"file://../../db/migrations/",
				"sqlite", driver)
			if err != nil {
				t.Errorf("%s: setup failed - DB migration setup: %v", th, err)
				return
			}
			if err = m.Up(); err != nil {
				t.Errorf("%s: setup failed - DB migration: %v", th, err)
				return
			}
			queries := repository.New(db)

			s := debsectracker.NewService(db, queries, tt.cfg)
			gotErr := s.IngestTriage(t.Context())
			if gotErr != nil {
				if tt.expectedError != nil {
					if !errors.Is(gotErr, tt.expectedError) { // XXX use specific errors
						t.Errorf("%s failed with: \"%v\"; expected: \"%v\"", th, gotErr, tt.expectedError)
					}
				} else {
					t.Errorf("%s failed with: '%v'", th, gotErr)
				}
				return
			}
			if tt.expectedError != nil {
				t.Fatalf("%s succeeded unexpectedly", th)
			}

			entries, err := getAllTriageEntriesWithRelationsFromDB(t.Context(), queries)
			if err != nil {
				t.Fatalf("%s failed: could not get the data from the DB: %v", th, err)
			}

			actualJSON, err := json.Marshal(entries)
			if err != nil {
				t.Fatalf(
					"%s failed: unexcepted problem while marshalling json the processed entries: %v",
					th,
					err,
				)
			}
			actualJSON, err = minifyJSON(actualJSON)
			if err != nil {
				t.Fatalf("%s failed: could not minify JSON of processed entries: %v", th, err)
			}

			jb, err := os.ReadFile(tt.expectedEntriesJSONPath)
			if err != nil {
				t.Fatalf("%s failed: could not read JSON file with expected entries: %v", th, err)
			}

			expectedJSON, err := minifyJSON(jb)
			if err != nil {
				t.Fatalf("%s failed: could not minify read JSON file: %v", th, err)
			}

			if !bytes.Equal(actualJSON, expectedJSON) {
				t.Errorf(
					"%s failed: actual entries does not match the expected ones: '%s' != '%s'",
					th,
					actualJSON,
					expectedJSON,
				)
			}
		})
	}
}
