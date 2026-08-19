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

func (f PackageListFormat) String() string {
	switch f {
	case InReleaseFormat:
		return "inrelease"
	case CycloneDXFormat:
		return "cyclonedx"
	default:
		return "unknown"
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

type options struct {
	Version string
	PkgFmt  string
	SBOMURL string
}

func Cmd() *cobra.Command {
	var opts options
	cmd := &cobra.Command{
		Use:     "packages",
		Short:   "Print packages of a <version>",
		GroupID: "debug",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd.Context(), opts)
		},
	}
	cmd.Flags().StringVar(&opts.Version, "version", "", "specific version. Required when pkgfmt=inrelease")
	cmd.Flags().StringVar(&opts.PkgFmt, "pkgfmt", "inrelease", "define packagelist format (inrelease,cyclonedx)")
	cmd.Flags().StringVar(
		&opts.SBOMURL,
		"sbomURL",
		"",
		"URL to sbom in cyclonedx format, required when pkgfmt=cyclonedx")

	return cmd
}

func run(ctx context.Context, opts options) error {
	pkgListFormat, err := parsePackageListFormat(opts.PkgFmt)
	if err != nil {
		return fmt.Errorf("unknown packagelist format %q", opts.PkgFmt)
	}

	var packages []Package
	switch pkgListFormat {
	case InReleaseFormat:
		if opts.Version == "" {
			return errors.New("version required when pkgfmt=inrelease")
		}
		var release version.GardenLinuxRelease
		release, err = version.MakeGardenLinuxReleaseFromString(opts.Version)
		if err != nil {
			return err
		}
		packages, err = GetPackageListsFromInRelease(ctx, release)
	case CycloneDXFormat:
		if opts.SBOMURL == "" {
			return errors.New("sbomURL required when pkgfmt=cyclonedx")
		}
		var sbomURL *url.URL
		sbomURL, err = url.Parse(opts.SBOMURL)
		if err != nil {
			return err
		}
		packages, err = GetPackageListsFromCycloneDx(ctx, sbomURL)
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
