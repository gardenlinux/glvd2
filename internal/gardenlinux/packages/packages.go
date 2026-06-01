package packages

import (
	"errors"
	"fmt"
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

func Cmd() (*cobra.Command, error) {
	cmd := &cobra.Command{
		Use:     "packages <version>",
		Short:   "Print packages of a <version>",
		GroupID: "debug",
		Args:    cobra.MaximumNArgs(3),
		RunE: func(cmd *cobra.Command, _ []string) error {
			var release version.GardenLinuxRelease
			var err error
			var packages *[]Package

			vers, _ := cmd.Flags().GetString("version")
			if len(vers) != 0 {
				release, err = version.MakeGardenLinuxReleaseFromString(vers)
				if err != nil {
					return err
				}
			}

			var pkgfmt string
			pkgfmt, err = cmd.Flags().GetString("pkgfmt")
			if err != nil {
				return err
			}

			pkgListFormat := PackageListFormatToEnum[pkgfmt]
			switch pkgListFormat {
			case InReleaseFormat:
				packages, err = GetPackageListsFromInRelease(release)
				if err != nil {
					return err
				}
			case CycloneDXFormat:
				var sbomUrl string
				sbomUrl, err = cmd.Flags().GetString("sbomUrl")
				if err != nil {
					return err
				}
				if len(sbomUrl) == 0 {
					return errors.New("sbomUrl required when pkgfmt=cyclonedx")
				}
				var cycloneDxUrl *url.URL
				cycloneDxUrl, err = url.Parse(sbomUrl)
				if err != nil {
					return err
				}
				fmt.Println("GetPackagesListFromCycloneDx")
				packages, err = GetPackageListsFromCycloneDx(cycloneDxUrl)
				if err != nil {
					return err
				}
			default:
				return fmt.Errorf("unknown packagelist format type %v", pkgListFormat)
			}

			fmt.Printf("v=%v", packages)
			fmt.Printf("Iterating over packages: %d", len(*packages))
			for _, pkg := range *packages {
				//nolint:revive,forbidigo // printing output for debugging
				fmt.Printf(
					"%s (%s) %s\n",
					pkg.Name,
					pkg.Architecture,
					pkg.Version,
				)
			}
			return nil
		},
	}
	cmd.Flags().String("version", "", "specific version. Required when pkgfmt=inrelease")
	cmd.Flags().String("pkgfmt", "inrelease", "define packagelist format (inrelease,cyclonedx)")
	cmd.Flags().String("sbomUrl", "", "URL to sbom in cyclonedx format, required when pkgfmt=cyclonedx")

	return cmd, nil
}
