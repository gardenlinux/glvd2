package packages

import (
	"fmt"
	"log/slog"

	cdx "github.com/CycloneDX/cyclonedx-go"
	packageurl "github.com/package-url/packageurl-go"
)

// isNonPackageComponentType reports whether a CycloneDX component type is not a software package.
// Unknown types are treated as package-like (they fall through to the Unknown bucket).
func isNonPackageComponentType(t cdx.ComponentType) bool {
	switch t {
	case cdx.ComponentTypeApplication,
		cdx.ComponentTypeFramework,
		cdx.ComponentTypeLibrary:
		return false
	case cdx.ComponentTypeOS,
		cdx.ComponentTypeContainer,
		cdx.ComponentTypeFile,
		cdx.ComponentTypeDevice,
		cdx.ComponentTypeDeviceDriver,
		cdx.ComponentTypeFirmware,
		cdx.ComponentTypePlatform,
		cdx.ComponentTypeData,
		cdx.ComponentTypeMachineLearningModel,
		cdx.ComponentTypeCryptographicAsset:
		return true
	}

	return false
}

// classifiedComponent pairs a component with its parsed package URL.
type classifiedComponent struct {
	Component cdx.Component
	PURL      packageurl.PackageURL
}

// classification partitions every SBOM component into exactly one bucket,
// so no component is silently dropped.
type classification struct {
	Deb     []classifiedComponent // pkg:deb components
	NonDeb  []classifiedComponent // non-deb packages (pkg:golang, pkg:npm, ...)
	Ignored []cdx.Component       // non-package components without a PURL (operating-system, file, ...)
	Unknown []cdx.Component       // must stay empty; otherwise we could have a coverage gap
}

// isEmpty reports whether the classification holds no components at all.
func (c classification) isEmpty() bool {
	return len(c.Deb)+len(c.NonDeb)+len(c.Ignored)+len(c.Unknown) == 0
}

// classifyComponents assigns each component to one of the classification buckets.
func classifyComponents(components []cdx.Component) classification {
	var c classification

	for _, comp := range components {
		if comp.PackageURL == "" {
			if isNonPackageComponentType(comp.Type) {
				c.Ignored = append(c.Ignored, comp)
			} else {
				c.Unknown = append(c.Unknown, comp)
			}

			continue
		}

		pkgurl, err := packageurl.FromString(comp.PackageURL)
		if err != nil {
			c.Unknown = append(c.Unknown, comp)

			continue
		}

		cc := classifiedComponent{Component: comp, PURL: pkgurl}
		if pkgurl.Type == packageurl.TypeDebian {
			c.Deb = append(c.Deb, cc)
		} else {
			c.NonDeb = append(c.NonDeb, cc)
		}
	}

	return c
}

// checkComponentCoverage logs the classification breakdown and returns an error
// if the Unknown bucket is non-empty, since that means a potential silent
// false-negative (a coverage gap).
func checkComponentCoverage(c classification) error {
	slog.Debug("SBOM component classification",
		slog.Int("deb", len(c.Deb)),
		slog.Int("non_deb", len(c.NonDeb)),
		slog.Int("ignored", len(c.Ignored)),
		slog.Int("unknown", len(c.Unknown)),
	)

	if len(c.Unknown) == 0 {
		return nil
	}

	names := make([]string, 0, len(c.Unknown))
	for _, comp := range c.Unknown {
		names = append(names, comp.Name)
	}

	return fmt.Errorf("%d unclassified SBOM components (potential coverage gap): %v", len(c.Unknown), names)
}
