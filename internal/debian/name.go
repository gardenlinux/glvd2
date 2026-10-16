// Package debian provides helpers for Debian policies like package naming.
package debian

import (
	"errors"
	"regexp"
)

// packageNameRegex matches a package name (binary or source) per Debian Policy 5.6.1.
var packageNameRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]+$`)

var (
	// ErrEmptyName is returned when a checked package name is empty.
	ErrEmptyName = errors.New("empty name")
	// ErrInvalidName is returned when a checked package name does not match the Debian package name grammar.
	ErrInvalidName = errors.New("does not match Debian package name grammar")
)

// ValidatePackageName returns a descriptive error when name is not a well-formed package name
// (binary or source) per Debian Policy 5.6.1.
func ValidatePackageName(name string) error {
	if name == "" {
		return ErrEmptyName
	}
	if !packageNameRegex.MatchString(name) {
		return ErrInvalidName
	}

	return nil
}
