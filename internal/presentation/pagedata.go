package presentation

import (
	"fmt"
	"path/filepath"
	"strings"
)

type breadcrumb struct {
	Label string
	URL   string
}

type commonData struct {
	Title       string
	Section     string
	PagePath    string
	Breadcrumbs []breadcrumb
}

type pageData interface {
	setPath(pagePath string)
}

// setPath injects the page's own path so Link resolves URLs relative to where the file is written.
func (d *commonData) setPath(pagePath string) {
	d.PagePath = pagePath
}

// shortSHA truncates a hex VCS revision to its first 7 characters,
// leaving non-hash values (e.g. "unknown") untouched.
func shortSHA(sha string) string {
	const shortLen = 7

	if len(sha) <= shortLen {
		return sha
	}

	for _, c := range sha {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return sha
		}
	}

	return sha[:shortLen]
}

// Link resolves an artifact path relative to this page, retaining any fragment.
func (d *commonData) Link(target string) (string, error) {
	file, fragment, hasFragment := strings.Cut(target, "#")

	rel, err := filepath.Rel(filepath.Dir(d.PagePath), filepath.FromSlash(file))
	if err != nil {
		return "", fmt.Errorf("linking %q from %q: %w", target, d.PagePath, err)
	}

	link := filepath.ToSlash(rel)

	if hasFragment {
		link += "#" + fragment
	}

	return link, nil
}
