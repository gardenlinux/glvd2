// Package buildinfo exposes the VCS revision embedded in the binary by the Go toolchain.
package buildinfo

import "runtime/debug"

// SHA returns the full VCS commit hash embedded at build time, or an empty string
// when the binary was not built from a versioned checkout (e.g. go run, tests).
func SHA() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" {
			return s.Value
		}
	}

	return ""
}
