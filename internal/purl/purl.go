// Package purl provides identity PURL canonicalization.
//
// An identity PURL is type + namespace + name with version and all qualifiers stripped.
// It is used as unique identifiers to match CVEs with packages.
package purl

import (
	"fmt"
	"strings"

	packageurl "github.com/package-url/packageurl-go"
)

const (
	// NamespaceDebian is the deb namespace for Debian-owned packages.
	NamespaceDebian = "debian"
	// NamespaceGardenLinux is the deb namespace for GardenLinux-owned packages.
	NamespaceGardenLinux = "gardenlinux"
)

// normalize parses raw PURL strings and returns a PackageURL with a lowercased type
// and the default debian namespace applied when type debian.
func normalize(raw string) (packageurl.PackageURL, error) {
	p, err := packageurl.FromString(raw)
	if err != nil {
		return packageurl.PackageURL{}, fmt.Errorf("parsing PURL %q: %w", raw, err)
	}

	p.Type = strings.ToLower(p.Type)
	p.Namespace = strings.ToLower(p.Namespace)

	if p.Type == packageurl.TypeDebian && p.Namespace == "" {
		p.Namespace = NamespaceDebian
	}

	return p, nil
}

// Canonicalize parses a raw PURL string and returns its canonical identity PURL:
// the normalized type, namespace and name with version, qualifiers and subpath stripped.
func Canonicalize(raw string) (string, error) {
	p, err := normalize(raw)
	if err != nil {
		return "", err
	}

	canon := packageurl.NewPackageURL(p.Type, p.Namespace, p.Name, "", nil, "")
	return canon.ToString(), nil
}

// CanonicalizeVersioned behaves like [Canonicalize] but keeps the version:
// it returns the normalized type, namespace, name and version with qualifiers and subpath stripped.
func CanonicalizeVersioned(raw string) (string, error) {
	p, err := normalize(raw)
	if err != nil {
		return "", err
	}

	if p.Version == "" {
		return "", fmt.Errorf("versioned PURL %q has no version", raw)
	}

	canon := packageurl.NewPackageURL(p.Type, p.Namespace, p.Name, p.Version, nil, "")
	return canon.ToString(), nil
}

// NamespaceOf returns the namespace of the PURL as parsed, applying the
// deb convention that an empty namespace means debian if type is debian.
// It returns an error if the PURL cannot be parsed.
func NamespaceOf(raw string) (string, error) {
	p, err := normalize(raw)
	if err != nil {
		return "", err
	}

	return p.Namespace, nil
}

// NamespaceVariants returns the canonical identity PURLs.
// For deb type with debian or gardenlinux namespaces, it returns both variants.
// All other PURLs get returned as is.
func NamespaceVariants(raw string) ([]string, error) {
	p, err := normalize(raw)
	if err != nil {
		return nil, err
	}

	if p.Type != packageurl.TypeDebian || (p.Namespace != NamespaceDebian && p.Namespace != NamespaceGardenLinux) {
		canon := packageurl.NewPackageURL(p.Type, p.Namespace, p.Name, "", nil, "").ToString()
		return []string{canon}, nil
	}

	debian := packageurl.NewPackageURL(p.Type, NamespaceDebian, p.Name, "", nil, "").ToString()
	gardenlinux := packageurl.NewPackageURL(p.Type, NamespaceGardenLinux, p.Name, "", nil, "").ToString()

	return []string{debian, gardenlinux}, nil
}
