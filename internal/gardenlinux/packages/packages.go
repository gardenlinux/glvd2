package packages

import (
	"fmt"

	"github.com/gardenlinux/glvd2/internal/purl"
	packageurl "github.com/package-url/packageurl-go"
)

// Package is a source-resolved package entry used with both formats.
type Package struct {
	Name         string
	Source       string
	Version      string
	Architecture string
	Namespace    string
}

// IdentityPURL returns the canonical, version-free source-name identity PURL
// (pkg:deb/<namespace>/<source>) for the package, using the package namespace.
func (p Package) IdentityPURL() (string, error) {
	raw := packageurl.NewPackageURL(packageurl.TypeDebian, p.Namespace, p.Source, "", nil, "").ToString()
	canon, err := purl.Canonicalize(raw)
	if err != nil {
		return "", fmt.Errorf("canonicalizing identity PURL %q: %w", raw, err)
	}

	return canon, nil
}
