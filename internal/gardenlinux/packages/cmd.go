package packages

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/gardenlinux/glvd2/internal/config"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/glrd"
	"github.com/spf13/cobra"
)

type options struct {
	Version string
	PkgFmt  string
	SBOMURL string
	Flavor  string
	Gitish  string
}

type PackageListFormat int

const (
	InReleaseFormat PackageListFormat = iota
	CycloneDXFormat
)

func (f PackageListFormat) String() string {
	switch f {
	case InReleaseFormat:
		return "inrelease"
	case CycloneDXFormat:
		return "cyclonedx"
	default:
		return "unknown format"
	}
}

func parsePackageListFormat(s string) (PackageListFormat, error) {
	switch s {
	case "inrelease":
		return InReleaseFormat, nil
	case "cyclonedx":
		return CycloneDXFormat, nil
	default:
		return 0, fmt.Errorf("unknown packagelist format %q", s)
	}
}

func Cmd(cfg *config.AppConfig) *cobra.Command {
	var opts options
	var err error

	cmd := &cobra.Command{
		Use:     "packages",
		Short:   "List packages/dependencies of a release <version>",
		GroupID: "debug",
		Args:    cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if strings.ToLower(opts.PkgFmt) == "cyclonedx" && opts.Flavor == "" {
				return fmt.Errorf("--flavor is required when --pkgfmt is %q", opts.PkgFmt)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd.Context(), cfg, opts)
		},
	}
	cmd.Flags().StringVar(&opts.Version, "version", "", "release version")
	cmd.Flags().StringVar(&opts.Flavor, "flavor", "", "image flavor")
	cmd.Flags().StringVar(&opts.PkgFmt, "pkgfmt", "cyclonedx", "define packagelist format (inrelease,cyclonedx)")
	cmd.Flags().StringVar(
		&opts.SBOMURL,
		"sbomURL",
		"",
		"Use this URL as SBOM source")

	err = cmd.MarkFlagRequired("version")
	if err != nil {
		panic(err)
	}

	return cmd
}

func run(ctx context.Context, cfg *config.AppConfig, opts options) error {
	var pkgListFormat PackageListFormat
	var err error

	pkgListFormat, err = parsePackageListFormat(opts.PkgFmt)
	if err != nil {
		return err
	}

	var release glrd.GardenLinuxRelease
	release, err = glrd.MakeGardenLinuxReleaseFromString(opts.Version)
	if err != nil {
		return err
	}

	if opts.Version == "" {
		return errors.New("a release version is always required")
	}

	var packages []Package
	switch pkgListFormat {
	case InReleaseFormat:
		packages, err = GetPackageListsFromInRelease(ctx, release)
	case CycloneDXFormat:
		var sbomURL *url.URL
		if len(opts.SBOMURL) == 0 { // Automatically build the SBOM URL from the github release page
			var glrdRelease glrd.Release
			glrdRelease, err = glrd.GetRelease(ctx, cfg.GLRDReleasesURL, release)
			if err != nil {
				return err
			}

			sbomURL, err = glrdRelease.LocateSBOM(opts.Flavor)
		} else { // URL for SBOM is provided (mostly debugging)
			sbomURL, err = url.Parse(opts.SBOMURL)
		}
		if err != nil {
			return err
		}

		packages, err = GetPackageListFromCycloneDx(ctx, sbomURL)
	default:
		return fmt.Errorf("unhandled packagelist format %v", pkgListFormat)
	}
	if err != nil {
		return err
	}

	for _, pkg := range packages {
		slog.Info("Packages",
			slog.String("name", pkg.Name),
			slog.String("architecture", pkg.Architecture),
			slog.String("version", pkg.Version),
		)
	}
	return nil
}
