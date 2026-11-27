package presentation

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/gardenlinux/glvd2/internal/assessment"
)

var safeSegmentRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

var packageNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]+$`)

// SiteURLs identifies pages within the artifact. Templates make these paths relative to the current page.
type SiteURLs struct{}

func (u SiteURLs) Root() string {
	return "index.html"
}

func (u SiteURLs) Releases() string {
	return "releases/index.html"
}

func (u SiteURLs) CVEs() string {
	return "cves/index.html"
}

func (u SiteURLs) Statistics() string {
	return "statistics/index.html"
}

func (u SiteURLs) Packages() string {
	return "packages/index.html"
}

func (u SiteURLs) Package(name string) (string, error) {
	if !packageNameRe.MatchString(name) {
		return "", fmt.Errorf("invalid Debian source package name %q", name)
	}
	if name == "index.html" {
		return "", errors.New("package name conflicts with the package listing")
	}

	return "packages/" + name + "/index.html", nil
}

func (u SiteURLs) Release(version string) (string, error) {
	if err := validatePathSegment(version); err != nil {
		return "", fmt.Errorf("release version %q: %w", version, err)
	}

	return "releases/" + version + "/index.html", nil
}

func (u SiteURLs) Flavor(version, flavor string) (string, error) {
	if err := validatePathSegment(version); err != nil {
		return "", fmt.Errorf("release version %q: %w", version, err)
	}
	if err := validatePathSegment(flavor); err != nil {
		return "", fmt.Errorf("flavor name %q: %w", flavor, err)
	}

	return "releases/" + version + "/flavors/" + flavor + "/index.html", nil
}

func (u SiteURLs) CVE(id string) (string, error) {
	if err := assessment.ValidateCVEID(id); err != nil {
		return "", fmt.Errorf("CVE ID %q: %w", id, err)
	}

	return "cves/" + id + "/index.html", nil
}

func validatePathSegment(s string) error {
	if s == "" {
		return errors.New("empty path segment")
	}
	if !safeSegmentRe.MatchString(s) {
		return fmt.Errorf("%q is not a valid path segment", s)
	}

	return nil
}
