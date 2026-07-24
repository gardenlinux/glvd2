package sliceutil

// Unique returns a new slice containing only the unique elements.
func Unique[T comparable](a []T) []T {
	// Allocate space ahead of time to optimize performance
	unique := make([]T, 0, len(a))
	seen := make(map[T]struct{}, len(a))

	for _, element := range a {
		// If the element is not in the 'seen' map, add it.
		if _, exists := seen[element]; !exists {
			seen[element] = struct{}{}
			unique = append(unique, element)
		}
	}

	return unique
}
