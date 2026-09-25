package packages

import (
	"fmt"

	"github.com/gardenlinux/glvd2/internal/purl"
)

// VendoredComponent is a non-deb component shipped inside a deb package,
// carrying its raw identifiers as they appear in the SBOM.
type VendoredComponent struct {
	PURL string
	CPE  string
}

// ShippedBy groups the vendored (non-deb) components that a single deb source package ships.
type ShippedBy struct {
	Target   Package
	Children []VendoredComponent
}

// indexByRef maps each component's bom-ref to its classified component.
// Components without a bom-ref cannot be referenced by a dependency edge and are skipped.
func indexByRef(components []classifiedComponent) map[string]classifiedComponent {
	byRef := make(map[string]classifiedComponent, len(components))
	for _, cc := range components {
		if cc.Component.BOMRef != "" {
			byRef[cc.Component.BOMRef] = cc
		}
	}

	return byRef
}

// debTargetOf resolves the deb-source identity Package (Source + Namespace) for a deb component,
// reusing the inventory source-extraction path.
func debTargetOf(cc classifiedComponent) (Package, error) {
	source, err := extractSource(cc.Component, cc.PURL)
	if err != nil {
		return Package{}, fmt.Errorf("extracting source: %w", err)
	}

	namespace, err := purl.NamespaceOf(cc.Component.PackageURL)
	if err != nil {
		return Package{}, fmt.Errorf("resolving namespace: %w", err)
	}

	return Package{Source: source, Namespace: namespace}, nil
}
