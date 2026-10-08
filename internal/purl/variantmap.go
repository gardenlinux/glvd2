package purl

import "fmt"

// VariantMap is keyed by canonical identity PURLs as inserted, but when using Get
// it will match for both deb- and gardenlinux-namespaces.
type VariantMap[V any] map[string]V

// Get returns the value stored under any namespace variant of the PURL.
// It returns an error if canonicalPURL cannot be parsed into its variants.
//
//nolint:ireturn // generic V return is intentional
func (m VariantMap[V]) Get(canonicalPURL string) (V, bool, error) {
	variants, err := NamespaceVariants(canonicalPURL)
	if err != nil {
		var zero V

		return zero, false, fmt.Errorf("deriving namespace variants for %q: %w", canonicalPURL, err)
	}

	for _, variant := range variants {
		if v, ok := m[variant]; ok {
			return v, true, nil
		}
	}

	var zero V

	return zero, false, nil
}
