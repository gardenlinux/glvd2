// Package pkgbuild analyzes a Garden Linux pkg-build.
// For each pkg-build it reads prepare_source and its patch folders once and
// produces two results: the build provenance (whether GL ships Debian's version
// lineage or its own) and patch-based fix-evidence (the CVEs the build
// demonstrably fixes via CVE-named patches).
package pkgbuild

// Provenance is the decision-oriented build classification. It shows if a package
// is taken from testing without modifications, with modifications or self-build
// from upstream.
type Provenance string

const (
	// ProvenanceTakenFromTesting means GL ships the Debian apt-pool lineage as-is (no GL patches).
	ProvenanceTakenFromTesting Provenance = "taken-from-testing"
	// ProvenancePatchedFromDebian means a Debian base plus patches. Still deb-versioned and usually comparable,
	// with a bias to escalation on borderline cases.
	ProvenancePatchedFromDebian Provenance = "patched-from-debian"
	// ProvenanceBuiltFromUpstream means GL's own lineage.
	// Doing a deb version comparison for it can wrongly clear a release.
	ProvenanceBuiltFromUpstream Provenance = "built-from-upstream"
	// ProvenanceUnknown marks a build that cannot be assessed automatically: either
	// the recipe lineage was unreadable, or it is upstream-built with no usable upstream version.
	ProvenanceUnknown Provenance = "unknown"
)

// Analysis is the per-pkg-build decision record.
type Analysis struct {
	PkgName    string       `json:"pkg_name"`
	Version    string       `json:"version"`
	PURL       string       `json:"purl"`
	Repo       string       `json:"repo,omitempty"`
	TagCommit  string       `json:"commit,omitempty"`
	Provenance Provenance   `json:"provenance"`
	FixedCVEs  []FixedCVE   `json:"fixed_cves,omitempty"`
	Signals    BuildSignals `json:"signals"`
}

// EvidenceKind identifies how a CVE was detected as fixed by a build.
type EvidenceKind string

const (
	// EvidenceKindPatchFilename is the fix-evidence kind for a CVE detected
	// from a CVE-named patch file enabled in a quilt series.
	EvidenceKindPatchFilename EvidenceKind = "patch-filename"
)

// FixedCVE records when a CVE was demonstrably fixed by a build.
type FixedCVE struct {
	ID   string       `json:"id"`
	Kind EvidenceKind `json:"kind"`
}

// BuildSignals are the raw signals observed for a pkg-build.
type BuildSignals struct {
	BuiltByGL       bool   `json:"built_by_gl"`                // a GL prepare_source recipe exists
	AptSrc          bool   `json:"apt_src"`                    // pulls source from a GL/Debian apt package
	SalsaSrc        bool   `json:"salsa_src"`                  // loads debian src from salsa.debian.org
	UpstreamSrc     bool   `json:"upstream_src"`               // loads src from the upstream project
	HasPatches      bool   `json:"has_patches"`                // applies a patch set
	UpstreamVersion string `json:"upstream_version,omitempty"` // usable upstream version the recipe declared, if any
}

// classify maps the observed build signals to the provenance enum.
func classify(s BuildSignals) Provenance {
	hasSrcFromDebian := s.AptSrc || s.SalsaSrc

	switch {
	case !s.BuiltByGL:
		return ProvenanceTakenFromTesting
	case hasSrcFromDebian && s.HasPatches:
		return ProvenancePatchedFromDebian
	case hasSrcFromDebian:
		return ProvenanceTakenFromTesting
	case s.UpstreamSrc && s.UpstreamVersion != "":
		return ProvenanceBuiltFromUpstream
	default:
		return ProvenanceUnknown
	}
}
