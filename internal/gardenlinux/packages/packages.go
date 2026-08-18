package packages

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"

	"github.com/gardenlinux/glvd2/internal/gardenlinux/version"
	"github.com/spf13/cobra"
)

type PackageListFormat int

const (
	InReleaseFormat PackageListFormat = iota
	CycloneDXFormat
)

//nolint:gochecknoglobals // not a global
var PackageListFormatToName = map[PackageListFormat]string{
	InReleaseFormat: "inrelease",
	CycloneDXFormat: "cyclonedx",
}

//nolint:gochecknoglobals // not a global
var PackageListFormatToEnum = map[string]PackageListFormat{
	"inrelease": InReleaseFormat,
	"cyclonedx": CycloneDXFormat,
}

type options struct {
	Version string
	PkgFmt  string
	SBOMURL string
}

func Cmd() *cobra.Command {
	var opts options
	cmd := &cobra.Command{
		Use:     "packages <version>",
		Short:   "Print packages of a <version>",
		GroupID: "debug",
		Args:    cobra.MaximumNArgs(3), //nolint:mnd // just three possible parameters
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd.Context(), opts)
		},
	}
	cmd.Flags().StringVar(&opts.Version, "version", "", "specific version. Required when pkgfmt=inrelease")
	cmd.Flags().StringVar(&opts.PkgFmt, "pkgfmt", "inrelease", "define packagelist format (inrelease,cyclonedx)")
	cmd.Flags().
		StringVar(&opts.SBOMURL, "sbomUrl", "", "URL to sbom in cyclonedx format, required when pkgfmt=cyclonedx")

	return cmd
}

func run(ctx context.Context, opts options) error {
	var release version.GardenLinuxRelease
	var err error
	var packages []Package

	if len(opts.Version) != 0 {
		release, err = version.MakeGardenLinuxReleaseFromString(opts.Version)
		if err != nil {
			return err
		}
	}

	pkgListFormat := PackageListFormatToEnum[opts.PkgFmt]
	switch pkgListFormat {
	case InReleaseFormat:
		packages, err = GetPackageListsFromInRelease(ctx, release)
		if err != nil {
			return err
		}
	case CycloneDXFormat:
		if len(opts.SBOMURL) == 0 {
			return errors.New("sbomUrl required when pkgfmt=cyclonedx")
		}
		var cycloneDxURL *url.URL
		cycloneDxURL, err = url.Parse(opts.SBOMURL)
		if err != nil {
			return err
		}
		packages, err = GetPackageListsFromCycloneDx(ctx, cycloneDxURL)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown packagelist format type %v", pkgListFormat)
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
