package sliceutil_test

import (
	"testing"

	"github.com/gardenlinux/glvd2/internal/sliceutil"
	"github.com/stretchr/testify/assert"
)

func TestUnique(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "empty slice",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "no duplicates",
			input:    []string{"a", "b", "c"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "all duplicates",
			input:    []string{"a", "a", "a"},
			expected: []string{"a"},
		},
		{
			name:     "some duplicates preserves order",
			input:    []string{"b", "a", "b", "c", "a", "d"},
			expected: []string{"b", "a", "c", "d"},
		},
		{
			name:     "single element",
			input:    []string{"x"},
			expected: []string{"x"},
		},
		{
			name:     "nil slice",
			input:    nil,
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := sliceutil.Unique(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestUniqueInt(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []int
		expected []int
	}{
		{
			name:     "integers with duplicates, preserve order",
			input:    []int{3, 1, 4, 1, 5, 9, 2, 6, 5, 3},
			expected: []int{3, 1, 4, 5, 9, 2, 6},
		},
		{
			name:     "empty int slice",
			input:    []int{},
			expected: []int{},
		},
		{
			name:     "no duplicates",
			input:    []int{42, 67, 3000},
			expected: []int{42, 67, 3000},
		},
		{
			name:     "all duplicates",
			input:    []int{42, 42, 42, 42},
			expected: []int{42},
		},
		{
			name:     "single element",
			input:    []int{9},
			expected: []int{9},
		},
		{
			name:     "nil slice",
			input:    nil,
			expected: []int{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := sliceutil.Unique(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
