package pkgbuild

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/gardenlinux/glvd2/internal/config"
	"github.com/spf13/cobra"
)

type analyzeOptions struct {
	PkgName string
	Version string
}

// Cmd builds the debug command for the pkg-build analyzer.
func Cmd(cfg *config.AppConfig) *cobra.Command {
	var opts analyzeOptions
	cmd := &cobra.Command{
		Use:     "pkgbuild",
		Short:   "Analyze a GL pkg-build",
		GroupID: "debug",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Usage is only relevant for arg/flag errors (raised before RunE);
			// silence it for runtime failures.
			cmd.SilenceUsage = true

			return runAnalyze(cmd, cfg, opts)
		},
	}
	cmd.Flags().StringVar(&opts.PkgName, "pkgName", "", "source package name")
	cmd.Flags().StringVar(&opts.Version, "version", "", "shipped source version")
	_ = cmd.MarkFlagRequired("pkgName")
	_ = cmd.MarkFlagRequired("version")

	return cmd
}

func runAnalyze(cmd *cobra.Command, cfg *config.AppConfig, opts analyzeOptions) error {
	fetcher, err := NewGitHubFetcher()
	if err != nil {
		return err
	}

	analyzer := NewAnalyzer(NewStore(cfg), fetcher)

	analysis, err := analyzer.Analyze(cmd.Context(), opts.PkgName, opts.Version)
	if err != nil {
		return fmt.Errorf("analyzing %s@%s: %w", opts.PkgName, opts.Version, err)
	}

	stdOutLogger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	stdOutLogger.
		With("pkgName", analysis.PkgName, "version", analysis.Version, "purl", analysis.PURL).
		Info("analysis",
			"provenance", analysis.Provenance,
			"fixedCves", analysis.FixedCVEs,
			"repo", analysis.Repo,
			"commit", analysis.TagCommit,
		)

	return nil
}
