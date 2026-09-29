package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"

	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/gardenlinux/glvd2/internal/audit"
	"github.com/gardenlinux/glvd2/internal/config"
	"github.com/gardenlinux/glvd2/internal/configpath"
	database "github.com/gardenlinux/glvd2/internal/db"
	"github.com/gardenlinux/glvd2/internal/debmap"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/glrd"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/inventory"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/packages"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/sbom"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/vendormap"
	"github.com/gardenlinux/glvd2/internal/git"
	"github.com/gardenlinux/glvd2/internal/glmap"
	"github.com/gardenlinux/glvd2/internal/ingestion/cvelistv5"
	"github.com/gardenlinux/glvd2/internal/ingestion/debsectracker"
	"github.com/gardenlinux/glvd2/internal/publish"
	"github.com/gardenlinux/glvd2/internal/reactor"
	"github.com/gardenlinux/glvd2/internal/repository"
	"github.com/gardenlinux/glvd2/internal/screening"
)

type pipelineFlags struct {
	SkipSubmoduleUpdate bool
	PublishLevel        publish.Level
}

type runSummary struct {
	Total, Created, Updated, Unchanged int
}

func runPipeline(ctx context.Context, cfg *config.AppConfig, flags pipelineFlags) error {
	committer := git.Committer{
		Name:  cfg.Committer.Name,
		Email: cfg.Committer.Email,
	}
	writer := git.NewWriter(".", committer)

	publishCfg := publish.Config{
		Target: publish.Target{
			Remote: cfg.Push.Remote,
			Branch: cfg.Push.Branch,
		},
		Level: flags.PublishLevel,
	}
	publisher := publish.NewService(publishCfg, writer)

	if err := publisher.VerifyBranch(ctx); err != nil {
		slog.Error(
			"branch check failed: not on the expected branch",
			slog.String("expectedBranch", cfg.Push.Branch),
			slog.Any("error", err),
		)
		return err
	}

	// Reconcile owned artifact paths to HEAD before run.
	commitGroups := createCommitGroups(cfg)
	if err := publisher.PrepareWorktree(ctx, commitGroups); err != nil {
		slog.Error("pre-run worktree reconcile failed", slog.Any("error", err))
		return err
	}

	// Reject foreign staged content, if publish level is push.
	if err := publisher.VerifyCleanIndexForPush(ctx); err != nil {
		slog.Error("clean-index check failed", slog.Any("error", err))
		return err
	}

	db, err := database.Regenerate(cfg.InternalSqliteDBPath)
	if err != nil {
		slog.Error("could not open database", slog.Any("error", err))
		return err
	}
	defer func() {
		if errDb := db.Close(); errDb != nil {
			slog.Error("error during closing of the database", slog.Any("error", errDb))
		}
	}()

	err = db.Ping()
	if err != nil {
		slog.Error("could not ping the database", slog.Any("error", err))
		return err
	}

	queries := repository.New(db)

	// Our external sources CVEListV5 and the Debian Security Tracker are added as git submodules.
	submoduleService := git.NewSubmoduleService()
	if flags.SkipSubmoduleUpdate {
		slog.Info("Skipping updating the git submodules, since corresponding flag is set")
	} else {
		err = submoduleService.GetLatest(ctx)
		if err != nil {
			slog.Error("Could not get the latest state of the submodules", slog.Any("error", err))
			return err
		}
	}

	debSecTrackerIngestion := debsectracker.NewService(db, queries, cfg)
	err = debSecTrackerIngestion.IngestTriage(ctx)
	if err != nil {
		slog.Error("Ingestion from Debian Security Tracker failed", slog.Any("error", err))
		return err
	}

	// TODO: Find CVEs that are only present in the Deb Sec Tracker, but not in our repo from CVEListV5 (reserved ones).

	cveV5Service := cvelistv5.NewService(cfg)
	idsForCVEs, err := cveV5Service.GetIDsForCVEs(ctx)
	if err != nil {
		return err
	}

	auditService := audit.NewService(cfg)

	if err = recordDebMappingAudit(ctx, queries, auditService, idsForCVEs); err != nil {
		return err
	}

	screener, err := buildScreener(ctx, cfg, auditService, debSecTrackerIngestion, idsForCVEs)
	if err != nil {
		return err
	}

	assessmentService, err := buildAssessmentService(ctx, cfg)
	if err != nil {
		return err
	}

	summary, err := processCVEs(ctx, cveV5Service, screener, assessmentService)
	if err != nil {
		return err
	}

	slog.Info("finished processing CVEs from CVEListV5",
		slog.Int("total", summary.Total),
		slog.Int("created", summary.Created),
		slog.Int("updated", summary.Updated))

	if err = publisher.Run(ctx, commitGroups, func(name string) string {
		return commitMessageForGroup(name, cfg, summary)
	}); err != nil {
		slog.Error("publishing artifacts failed", slog.Any("error", err))
		return err
	}

	return nil
}

// recordDebMappingAudit analyzes Debian package mappings and records the audit artifacts.
func recordDebMappingAudit(
	ctx context.Context,
	queries *repository.Queries,
	auditService *audit.Service,
	idsForCVEs cvelistv5.IDsForCVEs,
) error {
	debMapper, err := debmap.NewService(queries)
	if err != nil {
		return err
	}

	debMapping, debPkgIDIndex, err := debMapper.Analyze(ctx, idsForCVEs)
	if err != nil {
		return err
	}

	if err = auditService.Record("deb_mapping_result.json", debMapping); err != nil {
		return fmt.Errorf("recording audit artifact - debian mapping result: %w", err)
	}
	if err = auditService.Record("deb_package_identifiers.json", debPkgIDIndex); err != nil {
		return fmt.Errorf("recording audit artifact - debian package identifiers: %w", err)
	}

	return nil
}

func buildScreener(
	ctx context.Context,
	cfg *config.AppConfig,
	auditService *audit.Service,
	debian screening.DebianVerdictLookup,
	idsForCVEs cvelistv5.IDsForCVEs,
) (*screening.Service, error) {
	curated, vendored, inv, err := buildScreeningResolvers(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("building screening resolvers: %w", err)
	}

	if err = recordScreeningAudit(auditService, curated, inv, vendored); err != nil {
		return nil, err
	}

	return screening.NewService(curated, vendored, inv, debian, idsForCVEs), nil
}

func buildAssessmentService(ctx context.Context, cfg *config.AppConfig) (*assessment.Service, error) {
	assessmentStore := assessment.NewStore(cfg)

	gitReader := git.NewReader(".")

	baseline, err := assessment.NewBaseline(ctx, gitReader, cfg)
	if err != nil {
		return nil, fmt.Errorf("resolving baseline: %w", err)
	}

	assessmentService, err := assessment.NewService(ctx, assessmentStore, baseline, []assessment.Reactor{
		reactor.Log{Logger: slog.Default()},
	})
	if err != nil {
		return nil, fmt.Errorf("setting up CVE data service: %w", err)
	}

	return assessmentService, nil
}

func buildScreeningResolvers(
	ctx context.Context,
	cfg *config.AppConfig,
) (glmap.Rules, glmap.Rules, inventory.Set, error) {
	curated, err := glmap.New(configpath.DefaultGLSpecificMappingConfigPath)
	if err != nil {
		return glmap.Rules{}, glmap.Rules{}, inventory.Set{}, fmt.Errorf("loading curated GL-specific mapping: %w", err)
	}

	releaseSource := func(ctx context.Context) ([]glrd.Release, error) {
		return glrd.GetMaintainedReleases(ctx, cfg.GLRDReleasesURL)
	}
	invAcc := inventory.NewAccumulator()
	vmAcc := vendormap.NewAccumulator()

	locate := func(release glrd.Release, flavor string) (*url.URL, error) {
		return release.LocateSBOM(flavor)
	}

	if err = sbom.Feed(ctx, releaseSource, locate, packages.GetCycloneDx, invAcc, vmAcc); err != nil {
		return glmap.Rules{}, glmap.Rules{}, inventory.Set{}, fmt.Errorf("feeding SBOMs: %w", err)
	}

	inv, err := invAcc.Result()
	if err != nil {
		return glmap.Rules{}, glmap.Rules{}, inventory.Set{}, fmt.Errorf("building GL package inventory: %w", err)
	}

	vendored, err := vmAcc.Result()
	if err != nil {
		return glmap.Rules{}, glmap.Rules{}, inventory.Set{}, fmt.Errorf(
			"building vendored-inclusion resolver: %w",
			err,
		)
	}

	return curated, vendored, inv, nil
}

func recordScreeningAudit(
	auditService *audit.Service,
	curated glmap.Rules,
	inv inventory.Set,
	vendored glmap.Rules,
) error {
	artifacts := []struct {
		label    string
		filename string
		data     any
	}{
		{"GL-specific mapping", "gl_specific_mapping.json", curated.AuditEntries()},
		{"GL package inventory", "gl_package_inventory.json", inv.AuditEntries()},
		{"vendored inclusion", "vendored_inclusion.json", vendored.AuditEntries()},
	}

	for _, a := range artifacts {
		if err := auditService.Record(a.filename, a.data); err != nil {
			return fmt.Errorf("recording audit artifact - %s: %w", a.label, err)
		}
	}

	return nil
}

// processCVEs consumes the CVE stream, screens and persists each record, and returns a summary.
func processCVEs(
	ctx context.Context,
	cveV5Service *cvelistv5.Service,
	screener *screening.Service,
	assessmentService *assessment.Service,
) (runSummary, error) {
	resCh, errCh := cveV5Service.ReceiveCVEs(ctx)
	var summary runSummary
	for resCh != nil || errCh != nil { // || is important, otherwise not all CVEs are processed
		select {
		case <-ctx.Done():
			return summary, ctx.Err()
		case cve, ok := <-resCh:
			if !ok {
				resCh = nil
				continue
			}
			summary.Total++

			incoming := assessment.RecordFromCVEV5(cve)

			screened, err := screener.Screen(ctx, incoming)
			if err != nil {
				return summary, fmt.Errorf("screening %s: %w", incoming.ID, err)
			}
			incoming.Screening = screened

			_, cs, procErr := assessmentService.Process(ctx, incoming)
			if procErr != nil {
				return summary, fmt.Errorf("processing %s: %w", incoming.ID, procErr)
			}

			switch cs.Type {
			case assessment.Created:
				summary.Created++
			case assessment.Updated:
				summary.Updated++
			case assessment.Unchanged:
				summary.Unchanged++
			}

		case cveErr, ok := <-errCh:
			if !ok {
				errCh = nil
				continue
			}
			if cveErr != nil {
				slog.Error("Parsing the CVEs from CVEListV5 failed", slog.Any("error", cveErr))
				return summary, cveErr
			}
		}
	}

	return summary, nil
}
