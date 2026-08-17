package db

import (
	"log/slog"

	"github.com/gardenlinux/glvd2/internal/config"
	"github.com/spf13/cobra"
)

func RegenerateCmd(cfg *config.AppConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:          "regenerate",
		Short:        "regenerate database and apply migrations",
		GroupID:      "debug", //nolint:nolintlint // just for debug output
		SilenceUsage: false,
		Args:         cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			// Update database if necessary
			db, err := Regenerate(cfg.InternalSqliteDBPath)
			if err != nil {
				slog.Error("could not open database", slog.Any("error", err))
				return err
			}
			defer func() {
				if errDb := db.Close(); errDb != nil {
					slog.Error("error during closing of the database", slog.Any("error", errDb))
				}
			}()

			return nil
		},
	}

	return cmd
}
