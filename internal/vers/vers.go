// Package vers is a thin, PURL-free layer over the VERS engine from
// "github.com/git-pkgs/vers" used for version-range checking.
//
// Range construction, parsing and scheme selection stay direct library calls.
// This only adds [Evaluate] to avoid handling invalid version for a schema
// without noticing.
package vers

import (
	"fmt"

	lib "github.com/git-pkgs/vers"
)

// Result is the outcome of evaluating a validated version against a range.
type Result int

const (
	// Outside means the version is not in the range.
	Outside Result = iota
	// Within means the version is in the range.
	Within
	// Undecidable means the version is not well-formed under the range's scheme.
	Undecidable
)

func (r Result) String() string {
	switch r {
	case Outside:
		return "outside"
	case Within:
		return "within"
	case Undecidable:
		return "undecidable"
	default:
		return fmt.Sprintf("Result(%d)", int(r))
	}
}

// Evaluate reports whether version falls within range.
//
// The library's Contains method returns a confident bool even for un-orderable inputs.
// To avoid misclassifying a CVE because of this, we first evaluate the version via
// the library's own method  against its schema to avoid these kind of errors.
func Evaluate(r *lib.Range, version string) Result {
	if !lib.ValidWithScheme(version, r.Scheme) {
		return Undecidable
	}
	if r.Contains(version) {
		return Within
	}

	return Outside
}
