package main

import (
	"fmt"

	"github.com/gardenlinux/glvd2/internal/config"
	database "github.com/gardenlinux/glvd2/internal/db"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/glcve"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/glrd"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/packages"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/repos"
	"github.com/gardenlinux/glvd2/internal/logging"
	"github.com/gardenlinux/glvd2/internal/publish"
	"github.com/spf13/cobra"
)

func newRootCmd(cfg *config.AppConfig) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:          "glvd2",
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		Short:        "Garden Linux Vulnerability Database 2",
		Long:         "Ingests and triages CVEs for Garden Linux.",
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			logLevel, err := cmd.Flags().GetString("log-level")
			if err != nil {
				return err
			}
			return logging.Configure(logLevel)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			skipSubmoduleUpdates, err := cmd.Flags().GetBool("skip-submodule-updates")
			if err != nil {
				return err
			}

			publishStr, err := cmd.Flags().GetString("publish-level")
			if err != nil {
				return err
			}
			level, ok := publish.ParseLevel(publishStr)
			if !ok {
				return fmt.Errorf(
					"invalid --publish-level value %q: must be one \"none\", \"commit\", or \"push\"",
					publishStr,
				)
			}

			flags := pipelineFlags{
				SkipSubmoduleUpdate: skipSubmoduleUpdates,
				PublishLevel:        level,
			}
			err = runPipeline(cmd.Context(), cfg, flags)
			return err
		},
	}
	rootCmd.PersistentFlags().
		String("log-level", "debug", "specify log-level from: error > warn > info > debug > trace (default: debug)")
	rootCmd.Flags().
		Bool("skip-submodule-updates", false, "skip updating the submodules used for data ingestion")
	rootCmd.Flags().
		String("publish-level", "none", "artifact publishing level: none | commit | push")

	return rootCmd
}

func registerSubcommands(root *cobra.Command, cfg *config.AppConfig) {
	root.AddGroup(&cobra.Group{
		ID:    "debug",
		Title: "Debugging:",
	})

	factories := []func() *cobra.Command{
		glrd.Cmd,
		packages.Cmd,
		glcve.ReleasePageCmd,
		glcve.MentionedCVEsCmd,
		repos.PackagerepoCmd,
		repos.BranchCmd,
		func() *cobra.Command { return repos.MetaCmd(cfg) },
		func() *cobra.Command { return database.RegenerateCmd(cfg) },
	}
	for _, f := range factories {
		root.AddCommand(f())
	}
}
