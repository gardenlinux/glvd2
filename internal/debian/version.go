package debian

import "strings"

// UpstreamVersion returns the upstream portion of a Debian version.
// The epoch (before the first ':') and the Debian revision (after the last '-')
// are stripped, per Debian version grammar [epoch:]upstream_version[-revision].
func UpstreamVersion(debVersion string) string {
	v := debVersion
	if i := strings.IndexByte(v, ':'); i >= 0 {
		v = v[i+1:]
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		v = v[:i]
	}

	return v
}
