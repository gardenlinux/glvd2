package cpe

import (
	"errors"
	"strings"
)

// ErrUnknownFormat is returned by Parse when the string does not begin with a recognised CPE prefix.
var ErrUnknownFormat = errors.New("unknown cpe format (expected 'cpe:/' or 'cpe:2.3:')")

// Parse auto-detects the CPE format and delegates to ParseCPE22 or ParseCPE23.
func Parse(s string) (WFN, error) {
	switch {
	case strings.HasPrefix(s, "cpe:2.3:"):
		return ParseCPE23(s)
	case strings.HasPrefix(s, "cpe:/"):
		return ParseCPE22(s)
	default:
		return WFN{}, ErrUnknownFormat
	}
}
