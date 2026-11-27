package presentation

import "testing"

// Formatting boundaries are tested directly to avoid rendering thousands of CVE pages.
func TestFormatInteger(t *testing.T) {
	t.Parallel()

	const sep = ","
	cases := []struct {
		in   int
		want string
	}{
		{-2, "-2"},
		{0, "0"},
		{7, "7"},
		{42, "42"},
		{999, "999"},
		{1000, "1" + sep + "000"},
		{12345, "12" + sep + "345"},
		{100000, "100" + sep + "000"},
		{1234567, "1" + sep + "234" + sep + "567"},
		{-4200, "-4" + sep + "200"},
	}
	for _, tc := range cases {
		if got := formatInteger(tc.in); got != tc.want {
			t.Errorf("formatInteger(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestDisplayLabel(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   string
		want string
	}{
		{"", "Unknown"},
		{"affected", "Affected"},
		{"not-affected", "Not affected"},
		{"VERSION-FIXED", "Version fixed"},
		// A multi-byte first rune must be upper-cased whole, not sliced by byte.
		{"\u00e9lan", "\u00c9lan"},
	}
	for _, tc := range cases {
		if got := displayLabel(tc.in); got != tc.want {
			t.Errorf("displayLabel(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
