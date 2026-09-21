package packages

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/gardenlinux/glvd2/internal/debian"
	"github.com/gardenlinux/glvd2/internal/purl"
	"github.com/gardenlinux/glvd2/internal/whttp"
	"github.com/package-url/packageurl-go"
)

// syftSourceProperty is the CycloneDX component property syft uses to record
// the Debian source package name.
const syftSourceProperty = "syft:metadata:source"

// errNoComponents is returned when an SBOM contains no components.
var errNoComponents = errors.New("sbom has no components")

// FetchCycloneDx fetches and decodes a CycloneDX SBOM.
func FetchCycloneDx(ctx context.Context, sbomURL *url.URL) (*cdx.BOM, error) {
	return getCycloneDx(ctx, sbomURL)
}

func getCycloneDx(ctx context.Context, sbomURL *url.URL) (*cdx.BOM, error) {
	var err error
	var raw string

	client := whttp.NewClient()
	raw, _, err = client.GetString(ctx, sbomURL.String())
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

func convertSBOMToPackageList(input *cdx.BOM) ([]Package, error) {
	if input.Components == nil || len(*input.Components) == 0 {
		return nil, errNoComponents
	}

	// Classify every component up front so nothing is silently dropped.
	classified := classifyComponents(*input.Components)
	if err := checkComponentCoverage(classified); err != nil {
		return nil, err
	}

	pkgs := make([]Package, 0, len(classified.Deb))
	for _, cc := range classified.Deb {
		component := cc.Component
		pkgurl := cc.PURL

		if pkgurl.Name != component.Name {
			return nil, fmt.Errorf("package url name %q does not match component name %q", pkgurl.Name, component.Name)
		}

		if pkgurl.Version != component.Version {
			return nil, fmt.Errorf("package url version %q does not match component version %q for %q",
				pkgurl.Version, component.Version, component.Name)
		}

		if err := debian.ValidatePackageName(pkgurl.Name); err != nil {
			return nil, fmt.Errorf("invalid package name %q: %w", pkgurl.Name, err)
		}

		if pkgurl.Version == "" {
			return nil, fmt.Errorf("empty version for package %q", pkgurl.Name)
		}

		source, err := extractSource(component, pkgurl)
		if err != nil {
			return nil, fmt.Errorf("extracting source for package %q: %w", pkgurl.Name, err)
		}

		namespace, err := purl.NamespaceOf(component.PackageURL)
		if err != nil {
			return nil, fmt.Errorf("resolving namespace for package %q: %w", pkgurl.Name, err)
		}

		pkgs = append(pkgs, Package{
			Name:         pkgurl.Name,
			Source:       source,
			Version:      pkgurl.Version,
			Architecture: pkgurl.Qualifiers.Map()["arch"],
			Namespace:    namespace,
		})
	}

	return pkgs, nil
}

// extractSource returns the Debian source package name for a dpkg component.
func extractSource(component cdx.Component, pkgurl packageurl.PackageURL) (string, error) {
	// First check, if there is an "upstream" qualifier in the PURL.
	if upstream := pkgurl.Qualifiers.Map()["upstream"]; upstream != "" {
		name, _, _ := strings.Cut(upstream, "@")
		if err := debian.ValidatePackageName(name); err != nil {
			return "", fmt.Errorf("invalid upstream source name %q in qualifier %q: %w", name, upstream, err)
		}

		return name, nil
	}

	// Second option is the "syft:metadata:source" property.
	if component.Properties != nil {
		for _, prop := range *component.Properties {
			if prop.Name == syftSourceProperty && prop.Value != "" {
				if err := debian.ValidatePackageName(prop.Value); err != nil {
					return "", fmt.Errorf("invalid source name %q in %s property: %w",
						prop.Value, syftSourceProperty, err)
				}

				return prop.Value, nil
			}
		}
	}

	// Fallback: binary name, which dpkg uses as the source name when they are equal.
	if err := debian.ValidatePackageName(pkgurl.Name); err != nil {
		return "", fmt.Errorf("invalid source name fallback %q: %w", pkgurl.Name, err)
	}

	return pkgurl.Name, nil
}

func GetPackageListsFromCycloneDx(ctx context.Context, sbomURL *url.URL) ([]Package, error) {
	var err error
	var sbom *cdx.BOM

	sbom, err = getCycloneDx(ctx, sbomURL)
	if err != nil {
		return nil, err
	}

	return convertSBOMToPackageList(sbom)
}
