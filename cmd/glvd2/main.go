package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/gardenlinux/glvd2/internal/audit"
	"github.com/gardenlinux/glvd2/internal/config"
	database "github.com/gardenlinux/glvd2/internal/db"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/glcve"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/glrd"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/packages"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/repos"
	"github.com/gardenlinux/glvd2/internal/git"
	"github.com/gardenlinux/glvd2/internal/ingestion/cvelistv5"
	"github.com/gardenlinux/glvd2/internal/ingestion/debsectracker"
	"github.com/gardenlinux/glvd2/internal/logging"
	"github.com/gardenlinux/glvd2/internal/mapping"
	"github.com/gardenlinux/glvd2/internal/reactor"
	"github.com/gardenlinux/glvd2/internal/repository"
	"github.com/spf13/cobra"
	_ "modernc.org/sqlite"
)

func ingestCVEs(cfg *config.AppConfig, skipSubmoduleUpdate bool) error {
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

	ctx := context.Background()

	// CVEListV5 and the Debian Security Tracker are currently added as git submodules
	submoduleService, err := git.NewSubmoduleService(cfg)
	if err != nil {
		slog.Error("Could not initialize the submodule service", slog.Any("error", err))
		return err
	}
	if skipSubmoduleUpdate {
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
	cveDataService, err := assessment.NewService(ctx, assessmentStore, baseline, []assessment.Reactor{
		reactor.Log{Logger: slog.Default()},
	})
	if err != nil {
		return fmt.Errorf("setting up CVE data service: %w", err)
	}

	resCh, errCh := cveV5Service.ReceiveCVEs(ctx)
	var cveCounter, createdCount, updatedCount int
	for resCh != nil || errCh != nil { // || is important, otherwise not all CVEs are processed
		select {
		case cve, ok := <-resCh:
			if !ok {
				resCh = nil
				continue
			}
			cveCounter++

			incoming := assessment.RecordFromCVEV5(cve)

			_, cs, processErr := cveDataService.Process(ctx, incoming)
			if processErr != nil {
				slog.Error("processing record", slog.String("cve", incoming.ID), slog.Any("error", processErr))
				continue
			}

			switch cs.Type {
			case assessment.Created:
				createdCount++
			case assessment.Updated:
				updatedCount++
			case assessment.Unchanged:
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
		slog.Int("total", cveCounter),
		slog.Int("created", createdCount),
		slog.Int("updated", updatedCount))

	return nil
}

func cmd(cfg *config.AppConfig) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:          "glvd2",
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		Short:        "CVE-related tool for GL",
		Long:         "Tool to ingest CVEs and triage for GL.",
		PersistentPreRun: func(cmd *cobra.Command, _ []string) {
			var err error
			var logLevel string
			logLevel, err = cmd.Flags().GetString("log-level")
			if err != nil {
				slog.Error("getting loglevel failed", "error", err)
			}

			err = logging.Configure(logLevel)
			if err != nil {
				slog.Error("could not set log level", "error", err)
			}
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			skipSubmoduleUpdates, err := cmd.Flags().GetBool("skip-submodule-updates")
			if err != nil {
				return err
			}

			return ingestCVEs(cfg, skipSubmoduleUpdates)
		},
	}
	rootCmd.PersistentFlags().
		String("log-level", "debug", "specify log-level from: error > warn > info > debug > trace")
	rootCmd.PersistentFlags().
		Bool("skip-submodule-updates", false, "skip updating the submodules used for data ingestion")

	return rootCmd
}

func main() {
	var err error
	var rootCmd *cobra.Command
	var cfg *config.AppConfig

	cfg, err = config.LoadAppConfig("./config")
	if err != nil {
		slog.Error("Could not read the config file", slog.Any("error", err))
		return
	}

	// Main program call
	rootCmd = cmd(cfg)

	// Argument and subprogram handling
	rootCmd.AddGroup(&cobra.Group{
		ID:    "debug",
		Title: "Debugging:",
	})

	// Debug: GLRD
	var glrdCmd *cobra.Command
	glrdCmd, err = glrd.Cmd()
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	rootCmd.AddCommand(glrdCmd)

	// Debug: Packages
	var packagesCmd *cobra.Command
	packagesCmd, err = packages.Cmd()
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	rootCmd.AddCommand(packagesCmd)

	// Debug: ReleasePage
	var releasePageCmd *cobra.Command
	releasePageCmd, err = glcve.ReleasePageCmd()
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	rootCmd.AddCommand(releasePageCmd)

	// Debug: Mentioned CVEs
	var cvesCmd *cobra.Command
	cvesCmd, err = glcve.MentionedCVEsCmd()
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	rootCmd.AddCommand(cvesCmd)

	// Debug: Repos information
	var reposCmd *cobra.Command
	reposCmd, err = repos.PackagerepoCmd()
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	rootCmd.AddCommand(reposCmd)

	// Debug: Repo Branches information
	var repoBranchCmd *cobra.Command
	repoBranchCmd, err = repos.BranchCmd()
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	rootCmd.AddCommand(repoBranchCmd)

	// Debug: Repometa information
	var repoMetaCmd *cobra.Command
	repoMetaCmd, err = repos.MetaCmd(cfg)
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	rootCmd.AddCommand(repoMetaCmd)

	// Regenerate
	var regenerateCmd *cobra.Command
	regenerateCmd, err = database.RegenerateCmd(cfg)
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	rootCmd.AddCommand(regenerateCmd)

	// Execute
	if err = rootCmd.Execute(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}
