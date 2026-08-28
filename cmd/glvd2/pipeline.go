package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/gardenlinux/glvd2/internal/audit"
	"github.com/gardenlinux/glvd2/internal/config"
	database "github.com/gardenlinux/glvd2/internal/db"
	"github.com/gardenlinux/glvd2/internal/git"
	"github.com/gardenlinux/glvd2/internal/ingestion/cvelistv5"
	"github.com/gardenlinux/glvd2/internal/ingestion/debsectracker"
	"github.com/gardenlinux/glvd2/internal/mapping"
	"github.com/gardenlinux/glvd2/internal/publish"
	"github.com/gardenlinux/glvd2/internal/reactor"
	"github.com/gardenlinux/glvd2/internal/repository"
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

	mappingService, err := mapping.NewService(queries)
	if err != nil {
		return err
	}

	mappingResult, pkgIDIndex, err := mappingService.Analyze(ctx, idsForCVEs)
	if err != nil {
		return err
	}

	auditService := audit.NewService(cfg)
	if err = auditService.Record("mapping_result.json", mappingResult); err != nil {
		return fmt.Errorf("recording audit mapping result: %w", err)
	}
	if err = auditService.Record("package_index.json", pkgIDIndex); err != nil {
		return fmt.Errorf("recording audit package index: %w", err)
	}

	assessmentStore := assessment.NewStore(cfg)
	gitReader := git.NewReader(".")
	baseline, err := assessment.NewBaseline(ctx, gitReader, cfg)
	if err != nil {
		return fmt.Errorf("resolving baseline: %w", err)
	}
	assessmentService, err := assessment.NewService(ctx, assessmentStore, baseline, []assessment.Reactor{
		reactor.Log{Logger: slog.Default()},
	})
	if err != nil {
		return fmt.Errorf("setting up CVE data service: %w", err)
	}

	resCh, errCh := cveV5Service.ReceiveCVEs(ctx)
	var summary runSummary
	for resCh != nil || errCh != nil { // || is important, otherwise not all CVEs are processed
		select {
		case <-ctx.Done():
			return ctx.Err()
		case cve, ok := <-resCh:
			if !ok {
				resCh = nil
				continue
			}
			summary.Total++

			incoming := assessment.RecordFromCVEV5(cve)

			_, cs, processErr := assessmentService.Process(ctx, incoming)
			if processErr != nil {
				slog.Error("processing record", slog.String("cve", incoming.ID), slog.Any("error", processErr))
				continue
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
				return cveErr
			}
		}
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
