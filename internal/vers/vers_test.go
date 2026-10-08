// The tests pin the library's behavior at the points that are crucial for us
// s.t. changes introduced by library upgrades can be caught automatically.
package vers_test

import (
	"testing"

	"github.com/gardenlinux/glvd2/internal/vers"
	lib "github.com/git-pkgs/vers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLibraryParsesSupportedSchemes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  string
		scheme string
	}{
		{name: "deb", input: "vers:deb/<1.0-1", scheme: "deb"},
		{name: "generic", input: "vers:generic/>=1.0|<1.5", scheme: "generic"},
		// Library behavior: schema stays "go" or "golang", but in the VERS always "go" will be used.
		{name: "go", input: "vers:go/<v1.5.0", scheme: "go"},
		{name: "golang purl alias parses as golang", input: "vers:golang/<v1.5.0", scheme: "golang"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r, err := lib.Parse(tc.input)
			require.NoError(t, err)
			assert.Equal(t, tc.scheme, r.Scheme)
		})
	}
}

func TestLibraryRoundTripLossless(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		input      string
		scheme     string
		wantSerial string
	}{
		{
			name:       "deb epoch and suffixes",
			input:      "vers:deb/<2:1.0~rc1-1+deb12u2",
			scheme:     "deb",
			wantSerial: "vers:deb/<2:1.0~rc1-1+deb12u2",
		},
		{
			name:       "gl backport",
			input:      "vers:deb/8.21.0-2gl0~bp2150",
			scheme:     "deb",
			wantSerial: "vers:deb/8.21.0-2gl0~bp2150",
		},
		{
			name:       "generic multi-interval",
			input:      "vers:generic/>=1.0|<1.5|>=2.0|<2.5",
			scheme:     "generic",
			wantSerial: "vers:generic/>=1.0|<1.5|>=2.0|<2.5",
		},
		{
			name:       "go",
			input:      "vers:go/<v1.5.0",
			scheme:     "go",
			wantSerial: "vers:go/<v1.5.0",
		},
		// Special library behavior: schema stays "golang", but in the VERS "go" will be used.
		{
			name:       "golang canonicalizes to go",
			input:      "vers:golang/<v1.5.0",
			scheme:     "golang",
			wantSerial: "vers:go/<v1.5.0",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r, err := lib.Parse(tc.input)
			require.NoError(t, err)

			serial := lib.ToVersString(r, tc.scheme)
			assert.Equal(t, tc.wantSerial, serial)

			r2, err := lib.Parse(serial)
			require.NoError(t, err)
			assert.Equal(t, serial, lib.ToVersString(r2, r2.Scheme), "re-serialization must be stable")
		})
	}
}

type evalCase struct {
	name    string
	version string
	want    vers.Result
}

func TestEvaluate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		rangeInput string
		cases      []evalCase
	}{
		{
			// Everything below 2:1.0-1 is vulnerable and the epoch dominates ordering.
			name:       "deb ordering with epoch",
			rangeInput: "vers:deb/<2:1.0-1",
			cases: []evalCase{
				{name: "lower epoch is vulnerable", version: "1:9.9-9", want: vers.Within},
				{name: "same epoch lower upstream", version: "2:0.9-1", want: vers.Within},
				{name: "tilde pre-release sorts below", version: "2:1.0~rc1-1", want: vers.Within},
				{name: "at bound is fixed", version: "2:1.0-1", want: vers.Outside},
				{name: "binNMU above bound is fixed", version: "2:1.0-1+b1", want: vers.Outside},
				{name: "higher upstream is fixed", version: "2:1.1-1", want: vers.Outside},
			},
		},
		{
			// Same shape without an epoch: a bare version carries an implicit epoch of 0,
			// so any explicit epoch outranks this bound outright.
			name:       "deb ordering without epoch",
			rangeInput: "vers:deb/<1.0-1",
			cases: []evalCase{
				{name: "lower upstream is vulnerable", version: "0.9-1", want: vers.Within},
				{name: "lower revision is vulnerable", version: "1.0-0", want: vers.Within},
				{name: "tilde pre-release sorts below", version: "1.0~rc1-1", want: vers.Within},
				{name: "at bound is fixed", version: "1.0-1", want: vers.Outside},
				{name: "binNMU above bound is fixed", version: "1.0-1+b1", want: vers.Outside},
				{name: "higher upstream is fixed", version: "1.1-1", want: vers.Outside},
				{name: "explicit epoch outranks implicit zero", version: "1:0.1-1", want: vers.Outside},
			},
		},
		{
			// 1.0 and 1.0-0 are equal per dpkg.
			name:       "deb semantic equality",
			rangeInput: "vers:deb/1.0",
			cases: []evalCase{
				{name: "1.0 and 1.0-0 are semantically equal", version: "1.0-0", want: vers.Within},
			},
		},
		{
			// gl<N> build sorts above its base source version.
			name:       "gl build sorts above deb base source",
			rangeInput: "vers:deb/<2.3.5-0",
			cases: []evalCase{
				{name: "gl0 build sorts above base", version: "2.3.5-0gl0", want: vers.Outside},
				{name: "gl1 build sorts above base", version: "2.3.5-0gl1", want: vers.Outside},
			},
		},
		{
			// A still-vulnerable source built as gl variant stays below a higher fix.
			name:       "gl build stays below higher fix",
			rangeInput: "vers:deb/<2.3.6-0",
			cases: []evalCase{
				{name: "gl0 build below higher fix", version: "2.3.5-0gl0", want: vers.Within},
				{name: "gl1 build below higher fix", version: "2.3.5-0gl1", want: vers.Within},
			},
		},
		{
			// gl suffix sorts correctly.
			name:       "gl suffix ordering",
			rangeInput: "vers:deb/<2.3.5-0gl1",
			cases: []evalCase{
				{name: "gl0 sorts below gl1", version: "2.3.5-0gl0", want: vers.Within},
				{name: "gl2 sorts above gl1", version: "2.3.5-0gl2", want: vers.Outside},
			},
		},
		{
			// The ~bp package-version suffix sorts below the un-suffixed version,
			// while the +bp git-tag spelling sorts above.
			// Hence, this must be handled in the comparison code.
			name:       "gl backport suffix ordering",
			rangeInput: "vers:deb/<8.21.0-2gl0",
			cases: []evalCase{
				{
					name:    "~bp sorts below the un-suffixed version",
					version: "8.21.0-2gl0~bp2150",
					want:    vers.Within,
				},
				{
					name:    "+bp sorts above - flips the verdict",
					version: "8.21.0-2gl0+bp2150",
					want:    vers.Outside,
				},
			},
		},
		{
			// Vulnerable below 1.5 with the generic comparator.
			name:       "generic ordering",
			rangeInput: "vers:generic/<1.5",
			cases: []evalCase{
				{name: "numeric lower", version: "1.4", want: vers.Within},
				{name: "prefix shorter is lower", version: "1", want: vers.Within},
				{name: "pre-release sorts below release", version: "1.5-rc1", want: vers.Within},
				{name: "at bound", version: "1.5", want: vers.Outside},
				{name: "build metadata ignored above bound", version: "1.5+build.7", want: vers.Outside},
				{name: "higher numeric", version: "2.0", want: vers.Outside},
				{name: "parseable but unusual is ordered", version: "1.0-weird~stuff", want: vers.Within},
				{name: "unparseable operand is undecidable", version: "abc", want: vers.Undecidable},
				{name: "empty operand is undecidable", version: "", want: vers.Undecidable},
			},
		},
		{
			// Vulnerable below v1.5.0, compared with the Go comparator (distinct from generic):
			// release outranks pre-release and build metadata ignored.
			name:       "go ordering",
			rangeInput: "vers:go/<v1.5.0",
			cases: []evalCase{
				{name: "lower patch", version: "v1.4.0", want: vers.Within},
				{name: "pre-release sorts below release", version: "v1.5.0-rc1", want: vers.Within},
				{name: "at bound", version: "v1.5.0", want: vers.Outside},
				{name: "build metadata ignored above bound", version: "v1.5.0+meta", want: vers.Outside},
				{name: "higher minor", version: "v2.0.0", want: vers.Outside},
				// A Go pseudo-version is well-formed semver-like, so the comparator orders it rather than escalating.
				{name: "pseudo-version is ordered", version: "v0.0.0-20210101000000-abcdef123456", want: vers.Within},
				{name: "unparseable operand is undecidable", version: "garbage", want: vers.Undecidable},
			},
		},
	}

	for _, group := range tests {
		t.Run(group.name, func(t *testing.T) {
			t.Parallel()

			r, err := lib.Parse(group.rangeInput)
			require.NoError(t, err)

			for _, tc := range group.cases {
				t.Run(tc.name, func(t *testing.T) {
					t.Parallel()

					assert.Equal(t, tc.want, vers.Evaluate(r, tc.version))
				})
			}
		})
	}
}

// TestEvaluateUndecided pins the footgun that Evaluate aims to neutralize:
// for un-orderable input the library's Contains returns a confident bool.
func TestEvaluateUndecided(t *testing.T) {
	t.Parallel()

	generic, err := lib.Parse("vers:generic/<1.5")
	require.NoError(t, err)
	assert.True(t, generic.Contains("abc"), "raw Contains would flag invalid as Within")
	assert.Equal(t, vers.Undecidable, vers.Evaluate(generic, "abc"))

	deb, err := lib.Parse("vers:deb/<2.0")
	require.NoError(t, err)
	assert.False(t, deb.Contains("!!!!"), "raw Contains would clear invalid as Outside")
	assert.Equal(t, vers.Undecidable, vers.Evaluate(deb, "!!!!"))
}

func TestEvaluateBoundKinds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		interval lib.Interval
		in       []string
		out      []string
	}{
		{
			name:     "exclusive lower; exclusive upper",
			interval: lib.NewInterval("1.0", "2.0", false, false),
			in:       []string{"1.5"},
			out:      []string{"1.0", "2.0"},
		},
		{
			name:     "inclusive lower; inclusive upper",
			interval: lib.NewInterval("1.0", "2.0", true, true),
			in:       []string{"1.0", "1.5", "2.0"},
			out:      []string{"0.9", "2.1"},
		},
		{
			name:     "inclusive lower; exclusive upper",
			interval: lib.NewInterval("1.0", "2.0", true, false),
			in:       []string{"1.0", "1.9"},
			out:      []string{"2.0"},
		},
		{
			name:     "inclusive lower; unbounded upper",
			interval: lib.GreaterThanInterval("1.0", true),
			in:       []string{"1.0", "99.0"},
			out:      []string{"0.9"},
		},
		{
			name:     "unbounded lower; inclusive upper",
			interval: lib.LessThanInterval("2.0", true),
			in:       []string{"0.1", "2.0"},
			out:      []string{"2.1"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := lib.NewRange([]lib.Interval{tc.interval})
			r.Scheme = "generic"

			for _, v := range tc.in {
				assert.Equal(t, vers.Within, vers.Evaluate(r, v), "%s should be within", v)
			}
			for _, v := range tc.out {
				assert.Equal(t, vers.Outside, vers.Evaluate(r, v), "%s should be outside", v)
			}
		})
	}
}

func TestEvaluateMultiIntervalAndOpenRanges(t *testing.T) {
	t.Parallel()

	// Disjoint union [1.0,1.5) OR [2.0,2.5).
	multi, err := lib.Parse("vers:generic/>=1.0|<1.5|>=2.0|<2.5")
	require.NoError(t, err)

	for v, want := range map[string]vers.Result{
		"1.0": vers.Within, "1.4": vers.Within, "1.5": vers.Outside, "1.9": vers.Outside,
		"2.0": vers.Within, "2.4": vers.Within, "2.5": vers.Outside, "0.9": vers.Outside,
	} {
		assert.Equal(t, want, vers.Evaluate(multi, v), "version %s", v)
	}

	// Open range: everything from 1.0 up is vulnerable.
	open, err := lib.Parse("vers:generic/>=1.0")
	require.NoError(t, err)
	assert.Equal(t, vers.Within, vers.Evaluate(open, "99.0"))
	assert.Equal(t, vers.Outside, vers.Evaluate(open, "0.1"))
}

func TestLibraryBuildersRoundTrip(t *testing.T) {
	t.Parallel()

	// The dominant Debian shape: first-fixed/exclusive upper bound.
	fixed := lib.LessThan("2.3.5-0", false)
	fixed.Scheme = "deb"
	assert.Equal(t, "vers:deb/<2.3.5-0", lib.ToVersString(fixed, "deb"))
	assert.Equal(t, vers.Within, vers.Evaluate(fixed, "2.3.4-1"))
	assert.Equal(t, vers.Outside, vers.Evaluate(fixed, "2.3.5-0"))

	// Malformed input errors at parse time (distinct from an undecidable operand).
	_, err := lib.Parse("not-a-vers")
	require.Error(t, err)
}
