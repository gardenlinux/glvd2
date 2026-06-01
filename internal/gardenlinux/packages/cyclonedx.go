package packages

import (
	"log/slog"
	"net/url"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/gardenlinux/glvd2/internal/whttp"
	"github.com/package-url/packageurl-go"
)

func getCycloneDx(url *url.URL) (*cdx.BOM, error) {
	var err error
	var client *whttp.HTTPClient = whttp.NewClient()
	var raw string

	raw, _, err = client.GetString(url.String())
	if err != nil {
		return nil, err
	}

	sbom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(strings.NewReader(raw), cdx.BOMFileFormatJSON)
	if err = decoder.Decode(sbom); err != nil {
		return nil, err
	}
	return sbom, nil
}

func convertSbomToPackageList(input *cdx.BOM) (*[]Package, error) {
	var result []Package
	var err error

	for _, component := range *input.Components {
		var pkg Package
		var pkgurl packageurl.PackageURL
		pkgurl, err = packageurl.FromString(component.PackageURL)
		if err != nil {
			slog.Warn("unable to parse package url", "type", "sbom", "packagename", component.Name, "packageurl", component.PackageURL)
			continue
		}

		if pkgurl.Name != component.Name {
			slog.Warn("pkgurl name != component name", "name", component.Name, "pkgurl", pkgurl.Name, "component", component.Name)
		}

		if pkgurl.Version != component.Version {
			slog.Warn("pkgurl version != component version", "name", component.Name, "pkgurl", pkgurl.Version, "component", component.Version)
		}

		pkg.Name = pkgurl.Name
		pkg.Version = pkgurl.Version
		pkg.Architecture = pkgurl.Qualifiers.Map()["arch"]

		result = append(result, pkg)
	}

	return &result, nil
}

func GetPackageListsFromCycloneDx(url *url.URL) (*[]Package, error) {
	var err error
	var sbom *cdx.BOM

	sbom, err = getCycloneDx(url)
	if err != nil {
		return nil, err
	}

	return convertSbomToPackageList(sbom)
}
