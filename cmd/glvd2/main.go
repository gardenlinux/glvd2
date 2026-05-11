package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/gardenlinux/glvd2/internal/config"
	database "github.com/gardenlinux/glvd2/internal/db"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/glcve"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/glrd"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/packages"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/repos"
	"github.com/gardenlinux/glvd2/internal/git"
	"github.com/gardenlinux/glvd2/internal/ingestion"
	"github.com/gardenlinux/glvd2/internal/ingestion/debsectracker"
	"github.com/gardenlinux/glvd2/internal/repository"
	"github.com/spf13/cobra"
	_ "modernc.org/sqlite"
)

// Set the log level via environment variable.
func setLogLevel(logLevelStr string) error {
	var logLevel slog.LevelVar
	err := logLevel.UnmarshalText([]byte(logLevelStr))
	if err != nil {
		return err
	}

	logLevel.Set(slog.LevelInfo)

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: &logLevel,
	})))

	return nil
}

func ingestCVEs(cfg *config.AppConfig) error {
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
	err = submoduleService.GetLatest(ctx)
	if err != nil {
		slog.Error("Could not get the latest state of the submodules", slog.Any("error", err))
		return err
	}

	debSecTrackerIngestion := debsectracker.NewService(db, queries, cfg)
	err = debSecTrackerIngestion.IngestTriage(ctx)
	if err != nil {
		slog.Error("Ingestion from Debian Security Tracker: %w", slog.Any("error", err))
		return err
	}

	cveV5Ingestion := ingestion.NewCVEV5IngestionService(cfg)
	resCh, errCh := cveV5Ingestion.ReceiveCVEs()
	tmp := ""
	cveCounter := 0
	for resCh != nil && errCh != nil {
		select {
		case cve, ok := <-resCh:
			if !ok {
				resCh = nil
				continue
			}
			tmp = cve.Metadata.ID
			cveCounter++
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

	slog.Info("finished parsing the CVEs from CVEListV5",
		slog.Int("numberOfCVEs", cveCounter), slog.String("lastCVEParsed", tmp))

	return nil
}

func cmd(cfg *config.AppConfig) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:          "glvd2",
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		Short:        "CVE-related tool for GL",
		Long:         "Tool to ingest CVEs and triage for GL.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			logLevel, err := cmd.Flags().GetString("log-level")
			if err != nil {
				return err
			}

			err = setLogLevel(logLevel)
			if err != nil {
				return err
			}

			return ingestCVEs(cfg)
		},
	}
	rootCmd.PersistentFlags().String("log-level", "error", "specify log-level")

	return rootCmd
}

func main() {
	var err error
	var rootCmd *cobra.Command

	var cfg *config.AppConfig
	cfg, err = config.LoadAppConfig()
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

	// Debug: GRLD
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

	// Debug: Repo information
	var reposCmd *cobra.Command
	reposCmd, err = repos.Cmd()
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	rootCmd.AddCommand(reposCmd)

	// Execute
	if err = rootCmd.Execute(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}
