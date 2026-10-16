package purl_test

import (
	"testing"

	"github.com/gardenlinux/glvd2/internal/purl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMapGet_NamespaceVariantTolerant(t *testing.T) {
	t.Parallel()

	// Stored under the gardenlinux namespace only.
	m := purl.VariantMap[int]{"pkg:deb/gardenlinux/glibc": 42}

	for _, q := range []string{"pkg:deb/debian/glibc", "pkg:deb/gardenlinux/glibc"} {
		v, ok, err := m.Get(q)
		require.NoErrorf(t, err, "query %q", q)
		assert.Truef(t, ok, "query %q must hit", q)
		assert.Equal(t, 42, v)
	}
}

func TestMapGet_Miss(t *testing.T) {
	t.Parallel()

	m := purl.VariantMap[int]{"pkg:deb/debian/glibc": 1}

	v, ok, err := m.Get("pkg:deb/debian/wayland")
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Zero(t, v)
}

func TestMapGet_InvalidPURLReturnsError(t *testing.T) {
	t.Parallel()

	m := purl.VariantMap[int]{}

	_, ok, err := m.Get("not-a-purl")
	require.Error(t, err)
	assert.False(t, ok)
}
