package debian_test

import (
	"testing"

	"github.com/gardenlinux/glvd2/internal/debian"
	"github.com/stretchr/testify/assert"
)

func TestUpstreamVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "epoch and revision", input: "2:1.0-1", want: "1.0"},
		{name: "epoch only", input: "2:1.0", want: "1.0"},
		{name: "revision only", input: "1.0-1", want: "1.0"},
		{name: "no epoch no revision", input: "1.0", want: "1.0"},
		{name: "with gl build revision", input: "2.3.5-0gl1", want: "2.3.5"},
		{name: "upstream with hyphen keeps last split", input: "1.0-beta-1", want: "1.0-beta"},
		{name: "gl backport suffix", input: "8.21.0-2gl0~bp2150", want: "8.21.0"},

		// Since the function has no error path pin the output of ill-formed input.
		{name: "empty string", input: "", want: ""},
		{name: "epoch only no upstream", input: "2:", want: ""},
		{name: "trailing revision separator", input: "1.0-", want: "1.0"},
		{name: "leading revision separator", input: "-1.0", want: ""},
		{name: "leading epoch separator", input: ":1.0", want: "1.0"},
		{name: "bare revision separator", input: "-", want: ""},
		{name: "bare epoch separator", input: ":", want: ""},
		{name: "multiple epoch separators keep first split", input: "2:1:0-1", want: "1:0"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, debian.UpstreamVersion(tc.input))
		})
	}
}
