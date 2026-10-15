package pkgbuild

import (
	"net/url"
	"regexp"
	"strings"
)

// prepareScriptContent strips comments and joins backslash-continued lines so each logical command sits on one line.
func prepareScriptContent(content string) string {
	var buffer strings.Builder
	var result []string

	for line := range strings.SplitSeq(content, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}

		if body, continued := strings.CutSuffix(line, "\\"); continued {
			buffer.WriteString(body)
			continue
		}

		buffer.WriteString(line)
		result = append(result, strings.TrimSpace(buffer.String()))
		buffer.Reset()
	}

	if buffer.Len() > 0 {
		result = append(result, strings.TrimSpace(buffer.String()))
	}

	return strings.Join(result, "\n")
}

// analyzeRecipe extracts the build signals out of a prepared prepare_source script.
func analyzeRecipe(content string) BuildSignals {
	s := BuildSignals{BuiltByGL: true} // When there is a prepare_source file, we build it by definition.

	for line := range strings.Lines(content) {
		switch {
		case isCommand(line, "apt_src"):
			s.AptSrc = true
		case isCommand(line, "apply_patches") || isCommand(line, "import_upstream_patches"):
			s.HasPatches = true
		case isFetch(line):
			classifyFetch(line, &s)
		}
	}

	s.UpstreamVersion = extractUpstreamVersion(content)

	return s
}

// isCommand reports whether the line's leading token is name.
func isCommand(line, name string) bool {
	fields := strings.Fields(line)

	return len(fields) > 0 && fields[0] == name
}

// isFetch reports whether the line's leading command fetches source code.
func isFetch(line string) bool {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return false
	}

	cmd := fields[0]
	switch {
	case cmd == "git":
		return len(fields) > 1 && fields[1] == "clone"
	case strings.HasPrefix(cmd, "git_src"):
		return true
	case cmd == "curl" || cmd == "wget":
		return true
	default:
		return false
	}
}

// classifyFetch sets the source code origin signal for a fetch line based on its URL host:
// salsa is the Debian packaging VCS; any other non-Debian host is upstream.
// A plain debian.org host (apt pool / mirror) is left unclassified. It is covered by apt_src
// where relevant, and is too broad to attribute as either an upstream or a VCS source.
func classifyFetch(line string, s *BuildSignals) {
	host := fetchHost(line)
	switch {
	case host == "":
		return
	case host == "salsa.debian.org":
		s.SalsaSrc = true
	// TODO We have to evaluate how good this will work in practice.
	case isDebianHost(host):
		return
	default:
		s.UpstreamSrc = true
	}
}

// fetchHost returns the host of the first URL token on a line, or "" if there is none.
func fetchHost(line string) string {
	for field := range strings.FieldsSeq(line) {
		token := strings.Trim(field, `"'`)
		if !strings.Contains(token, "://") {
			continue
		}
		if u, err := url.Parse(token); err == nil {
			return u.Hostname()
		}
	}

	return ""
}

// isDebianHost reports whether host is debian.org or a subdomain of it.
func isDebianHost(host string) bool {
	return host == "debian.org" || strings.HasSuffix(host, ".debian.org")
}

var (
	upstreamVersionAssignment = regexp.MustCompile(`(?m)^\s*UPSTREAM_VERSION=(.+)$`)
	versionOrigAssignment     = regexp.MustCompile(`(?m)^\s*version_orig=(.+)$`)
)

// extractUpstreamVersion best-effort reads the upstream version a self-built pkg-build pulls.
// It returns "" when no unambiguous signal is present, which the caller treats as unknown (escalate).
// Only the dedicated upstream variables are consulted; a bare version= is the GL/Debian
// package version, not the upstream one, so it is deliberately not used here.
func extractUpstreamVersion(content string) string {
	ordered := []*regexp.Regexp{upstreamVersionAssignment, versionOrigAssignment}

	for _, re := range ordered {
		if m := re.FindStringSubmatch(content); m != nil {
			if v := cleanVersionValue(m[1]); v != "" {
				return v
			}
		}
	}

	return ""
}

// cleanVersionValue unquotes a shell assignment value and drops a leading "v".
// Values that reference other variables (e.g. "2:${version_orig}") are ambiguous and rejected.
// TODO Could we also cover the case where it is built up via other variables later?
func cleanVersionValue(raw string) string {
	v := strings.TrimSpace(raw)
	v = strings.Trim(v, `"'`)
	if v == "" || strings.ContainsAny(v, "${}") {
		return ""
	}
	return strings.TrimPrefix(v, "v")
}
