package debsectracker

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gardenlinux/glvd2/internal/config"
	"github.com/gardenlinux/glvd2/internal/model/debtriage"
	"github.com/gardenlinux/glvd2/internal/repository"
)

var (
	ErrMissingHeaderLine       = errors.New("missing triage entry header")
	ErrUnknownHeaderLineFormat = errors.New("unknown format for a triage entry header line")
	ErrUnknownFormat           = errors.New("unknown format for a triage entry")
)

type Service struct {
	db      *sql.DB
	queries *repository.Queries
	cfg     *config.AppConfig
}

func NewService(db *sql.DB, queries *repository.Queries, cfg *config.AppConfig) *Service {
	return &Service{
		db:      db,
		queries: queries,
		cfg:     cfg,
	}
}

type TriageEntry struct {
	Triage           repository.DebianTriage                  `json:"debian_triage"`
	AffectedPackages []repository.DebianTriageAffectedPackage `json:"affected_package"`
	AffectedReleases []repository.DebianTriageAffectedRelease `json:"affected_release"`
}

// processTriage is called by processLine once a complete triage entry is read and
// after all lines have been read to not miss the last entry.
func (s Service) processTriage(ctx context.Context, qtx *repository.Queries, entry *TriageEntry) error {
	if strings.HasSuffix(entry.Triage.CVEID, "-XXXX") {
		// Skipping entry, since there is no official CVE ID for it.
		return nil
	}

	if entry.Triage.Status == debtriage.StatusReserved ||
		entry.Triage.Status == debtriage.StatusRejected {
		// Skipping entry, since it is not disclosed yet or was rejected.
		return nil
	}

	_, err := qtx.InsertDebianTriage(ctx, repository.InsertDebianTriageParams(entry.Triage))
	if err != nil {
		return err
	}

	for _, pkg := range entry.AffectedPackages {
		_, pErr := qtx.InsertDebianPackageOrIgnore(ctx, pkg.PackageName)
		if pErr != nil && !errors.Is(pErr, sql.ErrNoRows) {
			return pErr
		}

		_, pErr = qtx.InsertDebianTriageAffectedPackage(ctx,
			repository.InsertDebianTriageAffectedPackageParams{
				// id is automatically set
				CVEID:       pkg.CVEID,
				PackageName: pkg.PackageName,
				Version:     pkg.Version,
				Info:        pkg.Info,
			})
		if pErr != nil {
			return pErr
		}
	}

	for _, rl := range entry.AffectedReleases {
		_, rErr := qtx.InsertDebianReleaseOrIgnore(ctx, rl.ReleaseName)
		if rErr != nil && !errors.Is(rErr, sql.ErrNoRows) {
			return rErr
		}

		_, rErr = qtx.InsertDebianTriageAffectedRelease(ctx,
			repository.InsertDebianTriageAffectedReleaseParams{
				CVEID:       rl.CVEID,
				ReleaseName: rl.ReleaseName,
				PackageName: rl.PackageName,
				Action:      rl.Action,
				Info:        rl.Info,
			})
		if rErr != nil {
			return rErr
		}
	}

	return nil
}

// CVE-YEAR-XXXX can be used, if there is not an official CVE ID yet.
var headerLineRegex = regexp.MustCompile(`^CVE-(?P<Year>\d+)-(?P<Number>\d+|XXXX).*\n$`)

var toDoCheckRegex = regexp.MustCompile(`^\tTODO: check\n$`)

var toDoNoteRegex = regexp.MustCompile(`^\tTODO: (?P<ToDoNote>.*)\n$`)

var notForUsRegex = regexp.MustCompile(`^\tNOT-FOR-US: (?P<Product>.*)\n$`)

var noteRegex = regexp.MustCompile(`^\tNOTE: (?P<Note>.*)\n$`)

var rejectedRegex = regexp.MustCompile(`^\tREJECTED\n$`)

var reservedRegex = regexp.MustCompile(`^\tRESERVED\n$`)

var packageRegex = regexp.MustCompile(`^\t- (?P<name>[^ ]+) (?P<v1>[^ ]+)( \((?P<info>.+)\))?\n$`)

var releaseRegex = regexp.MustCompile(
	`^\t\[(?P<release>.*)\] - (?P<name>[^ ]+) ` +
		`(?P<action>[^ ]+)( \((?P<info>.+)\))?\n$`)

var advisoryRegex = regexp.MustCompile(`^\t{.*}\n$`)

// processLine is called consecutively for all lines of the data/CVE file and calls itself processTriage once
// a triage entry has been read completely (a valid entry spans multiple lines).
func (s Service) processLine(ctx context.Context, qtx *repository.Queries,
	entry *TriageEntry, line string,
) (*TriageEntry, error) {
	// triage entries start with a header line like "CVE-2021-1222"
	headerMatches := headerLineRegex.FindStringSubmatch(line)
	if len(headerMatches) > 0 {
		if entry != nil {
			// process the previous triage entry, since a new one is started
			err := s.processTriage(ctx, qtx, entry)
			if err != nil {
				return nil, err
			}
		}

		cveID := fmt.Sprintf("CVE-%s-%s", headerMatches[1], headerMatches[2])
		entry = &TriageEntry{
			Triage: repository.DebianTriage{
				CVEID:    cveID,
				Status:   debtriage.StatusUnknown,
				NotForUs: "",
				Notes:    "",
				ToDos:    "",
			},
			AffectedPackages: []repository.DebianTriageAffectedPackage{},
			AffectedReleases: []repository.DebianTriageAffectedRelease{},
		}

		return entry, nil
	}
	if entry == nil {
		return nil, ErrMissingHeaderLine
	}

	if !strings.HasPrefix(line, "\t") {
		slog.Error("Unknown format for a triage entry header line",
			slog.String("ingestion", "Debian Security Tracker"),
			slog.String("input", line))

		return nil, ErrUnknownHeaderLineFormat
	}

	// must now be content for a previously opened triage entry

	notForUsMatch := notForUsRegex.FindStringSubmatch(line)
	if len(notForUsMatch) > 0 {
		entry.Triage.Status = debtriage.StatusNotForUs
		entry.Triage.NotForUs = notForUsMatch[1]

		return entry, nil
	}

	packageMatch := packageRegex.FindStringSubmatch(line)
	if len(packageMatch) > 0 {
		entry.Triage.Status = debtriage.StatusProcessed
		ap := repository.DebianTriageAffectedPackage{
			ID:          -1, // ignored while insertion
			CVEID:       entry.Triage.CVEID,
			PackageName: packageMatch[1],
			Version:     packageMatch[2],
			Info:        &packageMatch[4],
		}
		entry.AffectedPackages = append(entry.AffectedPackages, ap)

		return entry, nil
	}

	releaseMatch := releaseRegex.FindStringSubmatch(line)
	if len(releaseMatch) > 0 {
		entry.Triage.Status = debtriage.StatusProcessed
		ri := repository.DebianTriageAffectedRelease{
			ID:          -1, // ignored while insertion
			CVEID:       entry.Triage.CVEID,
			ReleaseName: releaseMatch[1],
			PackageName: releaseMatch[2],
			Action:      releaseMatch[3],
			Info:        &releaseMatch[5],
		}
		entry.AffectedReleases = append(entry.AffectedReleases, ri)

		return entry, nil
	}

	advisoryMatch := advisoryRegex.FindStringSubmatch(line)
	if len(advisoryMatch) > 0 {
		return entry, nil // not used for now
	}

	toDoCheckMatch := toDoCheckRegex.FindStringSubmatch(line)
	if len(toDoCheckMatch) > 0 {
		entry.Triage.Status = debtriage.StatusToDo

		return entry, nil
	}

	toDoNoteMatch := toDoNoteRegex.FindStringSubmatch(line)
	if len(toDoNoteMatch) > 0 {
		entry.Triage.ToDos += toDoNoteMatch[1] + "\n"

		return entry, nil
	}

	noteMatch := noteRegex.FindStringSubmatch(line)
	if len(noteMatch) > 0 {
		entry.Triage.Notes += noteMatch[1] + "\n"

		return entry, nil
	}

	rejectedMatch := rejectedRegex.FindStringSubmatch(line)
	if len(rejectedMatch) > 0 {
		entry.Triage.Status = debtriage.StatusRejected

		return entry, nil
	}

	reservedMatch := reservedRegex.FindStringSubmatch(line)
	if len(reservedMatch) > 0 {
		entry.Triage.Status = debtriage.StatusReserved

		return entry, nil
	}

	slog.Error("Unknown format for a triage entry",
		slog.String("ingestion", "Debian Security Tracker"),
		slog.String("input", line))

	return nil, ErrUnknownFormat
}

func (s Service) parseTriageList(ctx context.Context, fp string) error {
	fp = filepath.Clean(fp)
	if !strings.HasPrefix(fp, filepath.Clean(s.cfg.DebSecTrackerSubRepoPath)) {
		slog.Error("Prefix does not match",
			slog.String("filepath", fp), slog.String("expectedPrefix", s.cfg.DebSecTrackerSubRepoPath))
		return errors.New("unsafe file path used")
	}
	f, err := os.Open(fp)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			slog.Error("Error while closing file",
				slog.Any("error", err))
		}
	}()

	// commit all changes in one transaction to speed up the insertion
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelSerializable,
		ReadOnly:  false,
	})
	if err != nil {
		return err
	}
	defer func() {
		if txErr := tx.Rollback(); txErr != nil && !errors.Is(txErr, sql.ErrTxDone) {
			slog.Error("Error while rolling back transaction",
				slog.Any("error", txErr))
		}
	}()
	qtx := s.queries.WithTx(tx)

	entry := (*TriageEntry)(nil)
	scanner := bufio.NewReader(f)
	for {
		line, lErr := scanner.ReadString('\n')
		if lErr == io.EOF {
			if len(line) > 0 {
				var lpErr error
				entry, lpErr = s.processLine(ctx, qtx, entry, line)
				if lpErr != nil {
					return fmt.Errorf("error reading line from 'data/CVE/list': %w", lpErr)
				}
			}
			tErr := s.processTriage(ctx, qtx, entry) // ensures that also the last entry is processed
			if tErr != nil {
				return tErr
			}

			break
		}
		if lErr != nil {
			return fmt.Errorf("error reading line from 'data/CVE/list': %w", lErr)
		}
		var lpErr error
		entry, lpErr = s.processLine(ctx, qtx, entry, line)
		if lpErr != nil {
			return fmt.Errorf("error reading line from 'data/CVE/list': %w", lpErr)
		}
	}

	return tx.Commit()
}

func (s Service) IngestTriage(ctx context.Context) error {
	slog.Info("Ingesting from Debian Security Tracker")

	err := s.parseTriageList(ctx, s.cfg.DebSecTrackerSubRepoPath+"/data/CVE/list")
	if err != nil {
		return err
	}

	slog.Info("Finished ingestion from Debian Security Tracker")

	return nil
}

func (s Service) getTriageEntryFromDB(ctx context.Context, cveID string) (*TriageEntry, error) {
	debTriage, err := s.queries.GetDebianTriage(ctx, cveID)
	if err != nil {
		return nil, err
	}

	affectedPackages, pErr := s.queries.ListAffectedPackagesForDebianTriage(ctx, debTriage.CVEID)
	if pErr != nil {
		return nil, pErr
	}

	affectedReleases, rErr := s.queries.ListAffectedReleasesForDebianTriage(ctx, debTriage.CVEID)
	if rErr != nil {
		return nil, rErr
	}

	return &TriageEntry{
		Triage:           debTriage,
		AffectedPackages: affectedPackages,
		AffectedReleases: affectedReleases,
	}, nil
}
