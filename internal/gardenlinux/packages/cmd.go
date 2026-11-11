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
	"github.com/gardenlinux/glvd2/internal/gardenlinux/sbom"
	"github.com/spf13/cobra"
)

type options struct {
	Version string
	PkgFmt  string
	SBOMURL string
	Flavor  string
}

type PackageListFormat int

const (
	InReleaseFormat PackageListFormat = iota
	CycloneDXFormat
)

const (
	InReleaseFormatStr = "inrelease"
	CycloneDXFormatStr = "cyclonedx"
)

func (f PackageListFormat) String() string {
	switch f {
	case InReleaseFormat:
		return InReleaseFormatStr
	case CycloneDXFormat:
		return CycloneDXFormatStr
	default:
		return "unknown format"
	}
}

func parsePackageListFormat(s string) (PackageListFormat, error) {
	switch strings.ToLower(s) {
	case InReleaseFormatStr:
		return InReleaseFormat, nil
	case CycloneDXFormatStr:
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
		PreRunE: func(_ *cobra.Command, _ []string) error {
			if strings.ToLower(opts.PkgFmt) == CycloneDXFormatStr && opts.Flavor == "" {
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
	cmd.Flags().StringVar(&opts.PkgFmt, "pkgfmt", CycloneDXFormatStr,
		fmt.Sprintf("define packagelist format (%s, %s)",
			InReleaseFormatStr,
			CycloneDXFormatStr))
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

	if err = glrd.ValidateVersion(opts.Version); err != nil {
		return err
	}

	var packages []Package
	switch pkgListFormat {
	case InReleaseFormat:
		packages, err = GetPackageListsFromInRelease(ctx, opts.Version)
	case CycloneDXFormat:
		var sbomURL *url.URL
		if len(opts.SBOMURL) == 0 { // Automatically build the SBOM URL from the github release page
			var glrdRelease glrd.Release
			glrdRelease, err = getRelease(ctx, cfg.GLRDReleasesURL, opts.Version)
			if err != nil {
				return err
			}

			sbomURL, err = sbom.BuildSBOMURL(glrdRelease, opts.Flavor)
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

// getRelease returns the GLRD release whose version string matches reqVersion.
func getRelease(ctx context.Context, releasesURL, reqVersion string) (glrd.Release, error) {
	releases, err := glrd.GetReleases(ctx, releasesURL)
	if err != nil {
		return glrd.Release{}, err
	}

	for _, release := range releases {
		if reqVersion == release.Version.String() {
			return release, nil
		}
	}

	return glrd.Release{}, errors.New("release not found")
}
