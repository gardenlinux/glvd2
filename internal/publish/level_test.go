package publish_test

import (
	"testing"

	"github.com/gardenlinux/glvd2/internal/publish"
	"github.com/stretchr/testify/assert"
)

func TestParseLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input  string
		want   publish.Level
		wantOK bool
	}{
		{input: "none", want: publish.LevelNone, wantOK: true},
		{input: "commit", want: publish.LevelCommit, wantOK: true},
		{input: "push", want: publish.LevelPush, wantOK: true},
		{input: "foo", wantOK: false},
		{input: "", wantOK: false},
		{input: "PUSH", wantOK: false},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()

			got, ok := publish.ParseLevel(tc.input)
			assert.Equal(t, tc.wantOK, ok)
			if ok {
				assert.Equal(t, tc.want, got)
			}
		})
	}
}

func TestLevelString(t *testing.T) {
	t.Parallel()

	// Round-trip: String() -> ParseLevel() -> String() must be stable.
	for _, l := range []publish.Level{publish.LevelNone, publish.LevelCommit, publish.LevelPush} {
		got, ok := publish.ParseLevel(l.String())
		assert.True(t, ok, "ParseLevel(%q) returned false", l.String())
		assert.Equal(t, l, got)
	}
}
