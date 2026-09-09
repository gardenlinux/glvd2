package debsectracker_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"testing"

	"github.com/gardenlinux/glvd2/internal/config"
	"github.com/gardenlinux/glvd2/internal/ingestion/debsectracker"
	"github.com/gardenlinux/glvd2/internal/repository"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/sqlite"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestService sets up an in-memory SQLite database with the migrations applied.
func newTestService(t *testing.T, cfg *config.AppConfig) (*debsectracker.Service, *repository.Queries) {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	// With modernc.org/sqlite each connection to :memory: is a separate database.
	// Pin the pool to one connection so migrations and queries share the same schema.
	db.SetMaxOpenConns(1)

	driver, err := sqlite.WithInstance(db, &sqlite.Config{NoTxWrap: true})
	require.NoError(t, err)

	m, err := migrate.NewWithDatabaseInstance("file://../../db/migrations/", "sqlite", driver)
	require.NoError(t, err)
	require.NoError(t, m.Up())

	queries := repository.New(db)

	return debsectracker.NewService(db, queries, cfg), queries
}

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

type IngestTriageTestCase struct {
	name                    string
	cfg                     *config.AppConfig
	expectedEntriesJSONPath string
	expectedError           error // Use nil, if no error is expected.
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

func TestService_GetTriageEntryFromDB(t *testing.T) {
	t.Parallel()

	cfg := &config.AppConfig{
		DebSecTrackerSubRepoPath: "./testdata/validentrytest/debsectracker",
	}
	s, _ := newTestService(t, cfg)
	require.NoError(t, s.IngestTriage(t.Context()))

	tests := []struct {
		name          string
		cveID         string
		expectedError error
		assertEntry   func(t *testing.T, entry *debsectracker.TriageEntry)
	}{
		{
			name:  "existing entry",
			cveID: "CVE-2025-15281",
			assertEntry: func(t *testing.T, entry *debsectracker.TriageEntry) {
				t.Helper()
				assert.Equal(t, "CVE-2025-15281", entry.Triage.CVEID)
				assert.Len(t, entry.AffectedPackages, 1)
				assert.Equal(t, "glibc", entry.AffectedPackages[0].PackageName)
				assert.Len(t, entry.AffectedReleases, 3)
			},
		},
		{
			name:          "unknown entry",
			cveID:         "CVE-9999-0000",
			expectedError: sql.ErrNoRows,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			entry, err := s.GetTriageEntryFromDB(t.Context(), tt.cveID)
			if tt.expectedError != nil {
				require.ErrorIs(t, err, tt.expectedError)
				assert.Nil(t, entry)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, entry)
			tt.assertEntry(t, entry)
		})
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
		genIngestTriageTestCase("multiple valid entries", "multipleentriestest", nil),
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

			s, queries := newTestService(t, tt.cfg)

			err := s.IngestTriage(t.Context())
			if tt.expectedError != nil {
				require.ErrorIs(t, err, tt.expectedError)
				return
			}
			require.NoError(t, err)

			entries, err := getAllTriageEntriesWithRelationsFromDB(t.Context(), queries)
			require.NoError(t, err)

			actualJSON, err := json.Marshal(entries)
			require.NoError(t, err)

			expectedJSON, err := os.ReadFile(tt.expectedEntriesJSONPath)
			require.NoError(t, err)

			assert.JSONEq(t, string(expectedJSON), string(actualJSON))
		})
	}
}
