package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/gardenlinux/glvd2/internal/config"
	database "github.com/gardenlinux/glvd2/internal/db"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/glrd"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/packages"
	"github.com/gardenlinux/glvd2/internal/git"
	"github.com/gardenlinux/glvd2/internal/ingestion"
	"github.com/spf13/cobra"
	_ "modernc.org/sqlite"
)

// Set the log level via environment variable
func set_log_level() {
	var logLevel slog.LevelVar
	if err := logLevel.UnmarshalText([]byte(os.Getenv("LOG_LEVEL"))); err != nil {
		logLevel.Set(slog.LevelInfo)
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: &logLevel,
	})))
}

var rootCmd = &cobra.Command{Use: "glvd2"}

func main() {
	// Argument and subprogram handling
	rootCmd.AddCommand(glrd.ReleasesCmd())
	rootCmd.AddCommand(packages.PackagesCmd())

	if err := rootCmd.Execute(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}

	ctx := context.Background()

	cfg, err := config.LoadAppConfig()
	if err != nil {
		slog.Error("Could not read the config file", slog.Any("error", err))
		return
	}

	db, err := database.Open()
	if err != nil {
		slog.Error("could not open database", slog.Any("error", err))
		return
	}
	defer func() {
		if errDb := db.Close(); errDb != nil {
			slog.Error("error during closing of the database", slog.Any("error", errDb))
		}
	}()

	err = db.Ping()
	if err != nil {
		slog.Error("could not ping the database", slog.Any("error", err))
		return
	}

	// TODO: clean DB and apply migrations

	submoduleService, err := git.NewSubmoduleService(cfg)
	if err != nil {
		slog.Error("Could not initialize the submodule service", slog.Any("error", err))
		return
	}
	err = submoduleService.GetLatest(ctx)
	if err != nil {
		slog.Error("Could not get the latest state of the submodules", slog.Any("error", err))
		return
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
				return
			}
		}
	}

	slog.Info("finished parsing the CVEs from CVEListV5",
		slog.Int("numberOfCVEs", cveCounter), slog.String("lastCVEParsed", tmp))
}
