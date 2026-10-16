package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"

	"github.com/gardenlinux/glvd2/internal/affectedness"
	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/gardenlinux/glvd2/internal/audit"
	"github.com/gardenlinux/glvd2/internal/config"
	"github.com/gardenlinux/glvd2/internal/configpath"
	"github.com/gardenlinux/glvd2/internal/cvelistv5"
	database "github.com/gardenlinux/glvd2/internal/db"
	"github.com/gardenlinux/glvd2/internal/debmap"
	"github.com/gardenlinux/glvd2/internal/debsectracker"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/glrd"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/inventory"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/packages"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/pkgbuild"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/sbom"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/shippedversions"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/vendormap"
	"github.com/gardenlinux/glvd2/internal/git"
	"github.com/gardenlinux/glvd2/internal/glmap"
	"github.com/gardenlinux/glvd2/internal/pkgsuggest"
	"github.com/gardenlinux/glvd2/internal/publish"
	"github.com/gardenlinux/glvd2/internal/reactor"
	"github.com/gardenlinux/glvd2/internal/releasestatus"
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

	debMapping, err := buildDebMapping(ctx, queries, auditService, idsForCVEs)
	if err != nil {
		return err
	}

	curated, vendored, inv, shippedIndex, err := buildSBOMProjections(ctx, cfg)
	if err != nil {
		return err
	}

	if err = recordAudits(auditService, curated, inv, vendored, shippedIndex); err != nil {
		return err
	}

	screener := screening.NewService(curated, vendored, inv, debSecTrackerIngestion, idsForCVEs)

	assessor, err := buildReleaseStatusAssessor(ctx, cfg, debSecTrackerIngestion, shippedIndex)
	if err != nil {
		return err
	}

	suggester := pkgsuggest.New(debMapping, idsForCVEs)

	assessmentService, err := buildAssessmentService(ctx, cfg, suggester)
	if err != nil {
		return err
	}

	summary, err := processCVEs(ctx, cveV5Service, screener, assessmentService, assessor)
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

func buildDebMapping(
	ctx context.Context,
	queries *repository.Queries,
	auditService *audit.Service,
	idsForCVEs cvelistv5.IDsForCVEs,
) (debmap.MatchingDebianPackages, error) {
	debMapper, err := debmap.NewService(queries)
	if err != nil {
		return debmap.MatchingDebianPackages{}, err
	}

	debMapping, debPkgIDIndex, err := debMapper.Analyze(ctx, idsForCVEs)
	if err != nil {
		return debmap.MatchingDebianPackages{}, err
	}

	if err = auditService.Record("deb_mapping_result.json", debMapping); err != nil {
		return debmap.MatchingDebianPackages{}, fmt.Errorf("recording audit artifact - debian mapping result: %w", err)
	}
	if err = auditService.Record("deb_package_identifiers.json", debPkgIDIndex); err != nil {
		return debmap.MatchingDebianPackages{}, fmt.Errorf(
			"recording audit artifact - debian package identifiers: %w",
			err,
		)
	}

	return debMapping, nil
}

func buildReleaseStatusAssessor(
	ctx context.Context,
	cfg *config.AppConfig,
	dst *debsectracker.Service,
	shippedIndex shippedversions.Index,
) (*releasestatus.Service, error) {
	fetcher, err := pkgbuild.NewGitHubFetcher()
	if err != nil {
		return nil, fmt.Errorf("building GitHub fetcher: %w", err)
	}
	analyzer := pkgbuild.NewAnalyzer(pkgbuild.NewStore(cfg), fetcher)

	verdicts, err := dst.NewVerdictIndex(ctx)
	if err != nil {
		return nil, fmt.Errorf("building Debian verdict index: %w", err)
	}

	resolver := affectedness.NewResolver(analyzer, verdicts)

	return releasestatus.NewService(resolver, shippedIndex), nil
}

func buildAssessmentService(
	ctx context.Context,
	cfg *config.AppConfig,
	suggester *pkgsuggest.Suggester,
) (*assessment.Service, error) {
	assessmentStore := assessment.NewStore(cfg)

	gitReader := git.NewReader(".")

	baseline, err := assessment.NewBaseline(ctx, gitReader, cfg)
	if err != nil {
		return nil, fmt.Errorf("resolving baseline: %w", err)
	}

	deadline := reactor.DebianVerdictDeadline{
		TimeToWait: cfg.Screening.EscalationWindow,
		Suggester:  suggester,
		Logger:     slog.Default(),
	}

	assessmentService, err := assessment.NewService(ctx, assessmentStore, baseline, []assessment.Reactor{
		reactor.Log{Logger: slog.Default()},
		deadline,
	})
	if err != nil {
		return nil, fmt.Errorf("setting up CVE data service: %w", err)
	}

	return assessmentService, nil
}

func buildSBOMProjections(
	ctx context.Context,
	cfg *config.AppConfig,
) (glmap.Rules, glmap.Rules, inventory.Set, shippedversions.Index, error) {
	curated, err := glmap.New(configpath.DefaultGLSpecificMappingConfigPath)
	if err != nil {
		return glmap.Rules{}, glmap.Rules{}, inventory.Set{}, shippedversions.Index{},
			fmt.Errorf("loading curated GL-specific mapping: %w", err)
	}

	releaseSource := func(ctx context.Context) ([]glrd.Release, error) {
		return glrd.GetMaintainedReleases(ctx, cfg.GLRDReleasesURL)
	}
	invAcc := inventory.NewAccumulator()
	vmAcc := vendormap.NewAccumulator()
	svAcc := shippedversions.NewAccumulator()

	locate := func(release glrd.Release, flavor string) (*url.URL, error) {
		return release.LocateSBOM(flavor)
	}

	if err = sbom.Feed(ctx, releaseSource, locate, packages.GetCycloneDx, invAcc, vmAcc, svAcc); err != nil {
		return glmap.Rules{}, glmap.Rules{}, inventory.Set{}, shippedversions.Index{}, fmt.Errorf(
			"feeding SBOMs: %w",
			err,
		)
	}

	inv, err := invAcc.Result()
	if err != nil {
		return glmap.Rules{}, glmap.Rules{}, inventory.Set{}, shippedversions.Index{},
			fmt.Errorf("building GL package inventory: %w", err)
	}

	vendored, err := vmAcc.Result()
	if err != nil {
		return glmap.Rules{}, glmap.Rules{}, inventory.Set{}, shippedversions.Index{}, fmt.Errorf(
			"building vendored-inclusion resolver: %w",
			err,
		)
	}

	shippedIndex, err := svAcc.Result()
	if err != nil {
		return glmap.Rules{}, glmap.Rules{}, inventory.Set{}, shippedversions.Index{},
			fmt.Errorf("building per-release versioned index: %w", err)
	}

	return curated, vendored, inv, shippedIndex, nil
}

func recordAudits(
	auditService *audit.Service,
	curated glmap.Rules,
	inv inventory.Set,
	vendored glmap.Rules,
	shippedIndex shippedversions.Index,
) error {
	artifacts := []struct {
		label    string
		filename string
		data     any
	}{
		{"GL-specific mapping", "gl_specific_mapping.json", curated.AuditEntries()},
		{"GL package inventory", "gl_package_inventory.json", inv.AuditEntries()},
		{"vendored inclusion", "vendored_inclusion.json", vendored.AuditEntries()},
		{"shipped version index", "shipped_versions_index.json", shippedIndex.AuditEntries()},
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
	assessor *releasestatus.Service,
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
			incoming := assessment.RecordFromCVEV5(cve)

			screened, err := screener.Screen(ctx, incoming)
			if err != nil {
				return summary, fmt.Errorf("screening %s: %w", incoming.ID, err)
			}
			incoming.Screening = screened

			status, statusErr := assessmentService.GlobalStatus(incoming)
			if statusErr != nil {
				return summary, fmt.Errorf("resolving global status for %s: %w", incoming.ID, statusErr)
			}
			if status == assessment.StatusRelevant {
				releases, assessErr := assessor.Assess(ctx, incoming, cve)
				if assessErr != nil {
					return summary, fmt.Errorf("assessing release status for %s: %w", incoming.ID, assessErr)
				}
				incoming.Releases = releases
			}

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

			summary.Total++
			if summary.Total%10_000 == 0 {
				slog.Info("CVE processing progress",
					slog.Int("processed", summary.Total),
					slog.Int("created", summary.Created),
					slog.Int("updated", summary.Updated),
					slog.Int("unchanged", summary.Unchanged))
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
