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

// GetCycloneDx fetches and decodes the CycloneDX SBOM at sbomURL.
func GetCycloneDx(ctx context.Context, sbomURL *url.URL) (*cdx.BOM, error) {
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

func GetPackageListFromCycloneDx(ctx context.Context, sbomURL *url.URL) ([]Package, error) {
	var err error
	var sbom *cdx.BOM

	sbom, err = GetCycloneDx(ctx, sbomURL)
	if err != nil {
		return nil, err
	}

	return PackageListFromSBOM(sbom)
}

// PackageListFromSBOM projects a CycloneDX SBOM to its source-resolved deb packages.
// Non-deb components are skipped; an unclassifiable component is an error to avoid potential coverage gaps.
func PackageListFromSBOM(bom *cdx.BOM) ([]Package, error) {
	var rawComponents []cdx.Component
	if bom.Components != nil {
		rawComponents = *bom.Components
	}

	components := classifyComponents(rawComponents)
	if components.isEmpty() {
		return nil, errNoComponents
	}
	if err := checkComponentCoverage(components); err != nil {
		return nil, err
	}

	pkgs := make([]Package, 0, len(components.Deb))
	for _, cc := range components.Deb {
		pkg, err := debPackageOf(cc)
		if err != nil {
			return nil, err
		}

		pkgs = append(pkgs, pkg)
	}

	return pkgs, nil
}

// VendoredFromSBOM projects a CycloneDX SBOM to its vendored-inclusion groups:
// for every deb component that ships non-deb components (direct dependency edges),
// it returns the deb-source target paired with the shipped components' raw identifiers.
//
// A deb component with no vendored (non-deb) children is skipped, so an SBOM
// with no vendored edges yields nil.
func VendoredFromSBOM(bom *cdx.BOM) ([]ShippedBy, error) {
	var rawComponents []cdx.Component
	if bom.Components != nil {
		rawComponents = *bom.Components
	}

	components := classifyComponents(rawComponents)

	var rawDependencies []cdx.Dependency
	if bom.Dependencies != nil {
		rawDependencies = *bom.Dependencies
	}

	graph := buildDependencyGraph(rawDependencies)
	nonDebByRef := indexByRef(components.NonDeb)

	var groups []ShippedBy
	for _, debCC := range components.Deb {
		childRefs := graph.dependsOn(debCC.Component.BOMRef)
		if len(childRefs) == 0 {
			continue
		}

		target, err := debTargetOf(debCC)
		if err != nil {
			return nil, fmt.Errorf("deriving deb source for %q: %w", debCC.Component.Name, err)
		}

		var children []VendoredComponent
		for _, childRef := range childRefs {
			childCC, isNonDeb := nonDebByRef[childRef]
			if !isNonDeb {
				continue
			}

			children = append(children, VendoredComponent{
				PURL: childCC.Component.PackageURL,
				CPE:  childCC.Component.CPE,
			})
		}

		if len(children) == 0 {
			continue
		}

		groups = append(groups, ShippedBy{Target: target, Children: children})
	}

	return groups, nil
}

// debPackageOf validates a classified deb component and resolves it to a Package.
func debPackageOf(cc classifiedComponent) (Package, error) {
	component := cc.Component
	pkgURL := cc.PURL

	if pkgURL.Name != component.Name {
		return Package{}, fmt.Errorf(
			"package url name %q does not match component name %q",
			pkgURL.Name,
			component.Name,
		)
	}

	if pkgURL.Version == "" {
		return Package{}, fmt.Errorf("empty version for package %q", pkgURL.Name)
	}

	if pkgURL.Version != component.Version {
		return Package{}, fmt.Errorf("package url version %q does not match component version %q for %q",
			pkgURL.Version, component.Version, component.Name)
	}

	if err := debian.ValidatePackageName(pkgURL.Name); err != nil {
		return Package{}, fmt.Errorf("invalid package name %q: %w", pkgURL.Name, err)
	}

	source, sourceVersion, err := extractSource(component, pkgURL)
	if err != nil {
		return Package{}, fmt.Errorf("extracting source for package %q: %w", pkgURL.Name, err)
	}

	namespace, err := purl.NamespaceOf(component.PackageURL)
	if err != nil {
		return Package{}, fmt.Errorf("resolving namespace for package %q: %w", pkgURL.Name, err)
	}

	// An explicit source version appears only when it differs from the binary version.
	// Absent means by definition that they are equal.
	if sourceVersion == "" {
		sourceVersion = pkgURL.Version
	}

	return Package{
		Name:          pkgURL.Name,
		Source:        source,
		Version:       pkgURL.Version,
		SourceVersion: sourceVersion,
		Architecture:  pkgURL.Qualifiers.Map()["arch"],
		Namespace:     namespace,
	}, nil
}

// extractSource returns the Debian source package name for a dpkg component and when available the source version.
func extractSource(component cdx.Component, pkgURL packageurl.PackageURL) (string, string, error) {
	if upstream := pkgURL.Qualifiers.Map()["upstream"]; upstream != "" {
		// The upstream qualifier is "source" or "source@sourceversion".
		name, sourceVersion, _ := strings.Cut(upstream, "@")
		if err := debian.ValidatePackageName(name); err != nil {
			return "", "", fmt.Errorf("invalid upstream source name %q in qualifier %q: %w", name, upstream, err)
		}

		return name, sourceVersion, nil
	}

	// Second option is the "syft:metadata:source" property.
	if component.Properties != nil {
		for _, prop := range *component.Properties {
			if prop.Name == syftSourceProperty && prop.Value != "" {
				if err := debian.ValidatePackageName(prop.Value); err != nil {
					return "", "", fmt.Errorf("invalid source name %q in %s property: %w",
						prop.Value, syftSourceProperty, err)
				}

				return prop.Value, "", nil
			}
		}
	}

	// Fallback: binary name, which dpkg uses as the source name when they are equal.
	if err := debian.ValidatePackageName(pkgURL.Name); err != nil {
		return "", "", fmt.Errorf("invalid source name fallback %q: %w", pkgURL.Name, err)
	}

	return pkgURL.Name, "", nil
}
