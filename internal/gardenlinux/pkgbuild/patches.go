package pkgbuild

import (
	"regexp"
	"strings"
)

const (
	defaultDebianPatchDir   = "patches"
	defaultUpstreamPatchDir = "upstream_patches"
)

// cveIDPattern matches a CVE identifier anywhere in a patch filename.
var cveIDPattern = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,}`)

type patchDirConfig struct {
	keyword    string
	defaultDir string
}

// appliedPatchDirs returns the distinct patch folders a prepare_source applies.
func appliedPatchDirs(content string) []string {
	options := []patchDirConfig{
		{keyword: "apply_patches", defaultDir: defaultDebianPatchDir},
		{keyword: "import_upstream_patches", defaultDir: defaultUpstreamPatchDir},
	}

	seen := map[string]bool{}
	var dirs []string

	for line := range strings.Lines(content) {
		for _, opt := range options {
			dir, ok := patchCommandDir(line, opt.keyword, opt.defaultDir)
			if !ok {
				continue
			}
			if !seen[dir] {
				seen[dir] = true
				dirs = append(dirs, dir)
			}
		}
	}

	return dirs
}

// patchCommandDir reports whether line invokes keyword as its leading command token
// and, if so, the patch directory it targets.
func patchCommandDir(line, keyword, defaultDir string) (string, bool) {
	fields := strings.Fields(line)
	if len(fields) == 0 || fields[0] != keyword {
		return "", false
	}
	if len(fields) > 1 {
		return fields[1], true
	}

	return defaultDir, true
}

// patchDirPattern allows plain relative path segments (letters, digits, dash, underscore)
// joined by single slashes. It matches real GL patch folders while rejecting an absolute path,
// traversal (dots are disallowed, so "."/".." cannot form), and any character that could alter
// a GitHub contents API request.
var patchDirPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*$`)

// safePatchDir reports whether dir is safe to interpolate into the contents API path.
func safePatchDir(dir string) bool {
	return patchDirPattern.MatchString(dir)
}

// enabledSeriesEntries parses a quilt series file, returning the applied patch
// paths. The package-build series reader applies every non-empty line verbatim
// as a patch filename (no quilt options); comment lines never occur in a released
// build, but are skipped defensively so a disabled entry is never read as evidence.
func enabledSeriesEntries(series string) []string {
	var entries []string

	for line := range strings.Lines(series) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entries = append(entries, line)
	}

	return entries
}

// cvesFromSeries extracts the CVE IDs named by enabled series entries, as fix-evidence
// of kind patch-filename. A patch present but not enabled in the series yields nothing.
func cvesFromSeries(series string) []FixedCVE {
	seen := map[string]bool{}
	var fixed []FixedCVE

	for _, entry := range enabledSeriesEntries(series) {
		id := cveIDPattern.FindString(entry)
		if id == "" {
			continue
		}
		id = strings.ToUpper(id)
		if seen[id] {
			continue
		}
		seen[id] = true
		fixed = append(fixed, FixedCVE{ID: id, Kind: EvidenceKindPatchFilename})
	}

	return fixed
}
