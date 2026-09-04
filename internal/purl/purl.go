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

// Origin classifies who owns a PURL: the Debian namespace or the GardenLinux namespace.
type Origin int

const (
	// OriginUnknown is returned for PURLs that do not match any known origin.
	OriginUnknown Origin = iota
	// OriginDebian covers pkg:deb/debian/... packages.
	OriginDebian
	// OriginGardenLinux covers pkg:deb/gardenlinux/... packages.
	OriginGardenLinux
)

// normalize parses raw PURL strings and returns a PackageURL with a lowercased type
// and the default debian namespace applied.
//
// Adding the default debian namespace is necessary, since the package-url library
// does not enforce a namespace for `pkg:deb` prefixes.
func normalize(raw string) (packageurl.PackageURL, error) {
	p, err := packageurl.FromString(raw)
	if err != nil {
		return packageurl.PackageURL{}, fmt.Errorf("parsing PURL %q: %w", raw, err)
	}

	p.Type = strings.ToLower(p.Type)
	p.Namespace = strings.ToLower(p.Namespace)
	if p.Type == packageurl.TypeDebian && p.Namespace == "" {
		p.Namespace = "debian"
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

// OriginOf returns who owns the PURL for this package.
// It returns OriginUnknown for any PURL that cannot be parsed or does not match a known origin.
func OriginOf(raw string) Origin {
	p, err := normalize(raw)
	if err != nil || p.Type != packageurl.TypeDebian {
		return OriginUnknown
	}

	switch p.Namespace {
	case "debian":
		return OriginDebian
	case "gardenlinux":
		return OriginGardenLinux
	}

	return OriginUnknown
}
