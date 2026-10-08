package purl_test

import (
	"testing"

	"github.com/gardenlinux/glvd2/internal/purl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCanonicalize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{
			name: "debian package already canonical",
			raw:  "pkg:deb/debian/curl",
			want: "pkg:deb/debian/curl",
		},
		{
			name: "debian package with version stripped",
			raw:  "pkg:deb/debian/curl@7.88.1",
			want: "pkg:deb/debian/curl",
		},
		{
			name: "debian package with version and qualifiers stripped",
			raw:  "pkg:deb/debian/curl@7.88.1?arch=amd64",
			want: "pkg:deb/debian/curl",
		},
		{
			name: "debian package with subpath stripped",
			raw:  "pkg:deb/debian/curl@7.88.1#usr/bin/curl",
			want: "pkg:deb/debian/curl",
		},
		{
			name: "debian package uppercase type lowercased",
			raw:  "pkg:DEB/debian/curl",
			want: "pkg:deb/debian/curl",
		},
		{
			name: "debian package mixed-case type and namespace",
			raw:  "pkg:DEB/DEBIAN/curl@1.0?arch=amd64",
			want: "pkg:deb/debian/curl",
		},
		{
			name: "debian package without namespace defaults to debian",
			raw:  "pkg:deb/curl@7.88.1",
			want: "pkg:deb/debian/curl",
		},
		{
			name: "gardenlinux package canonical",
			raw:  "pkg:deb/gardenlinux/curl",
			want: "pkg:deb/gardenlinux/curl",
		},
		{
			name: "gardenlinux package with version stripped",
			raw:  "pkg:deb/gardenlinux/curl@1.2.3",
			want: "pkg:deb/gardenlinux/curl",
		},
		{
			name: "gardenlinux package with qualifiers stripped",
			raw:  "pkg:deb/gardenlinux/curl@1.2.3?arch=amd64",
			want: "pkg:deb/gardenlinux/curl",
		},
		{
			name: "generic package with version and qualifiers stripped",
			raw:  "pkg:generic/openssl@3.0.0?checksum=sha256:abc",
			want: "pkg:generic/openssl",
		},
		{
			name: "golang package with namespace",
			raw:  "pkg:golang/github.com/foo/bar@v1.2.3",
			want: "pkg:golang/github.com/foo/bar",
		},
		{
			name:    "invalid purl - missing scheme",
			raw:     "deb/debian/curl",
			wantErr: true,
		},
		{
			name:    "invalid purl - empty string",
			raw:     "",
			wantErr: true,
		},
		{
			// The packageurl-go library treats pkg:/deb/curl as
			// type=debian, name=curl (leading slash stripped).
			name: "purl with leading slash treated as type=debian",
			raw:  "pkg:/deb/curl",
			want: "pkg:deb/debian/curl",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := purl.Canonicalize(tc.raw)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestCanonicalizeVersioned(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{
			name: "keeps version, strips qualifiers",
			raw:  "pkg:deb/debian/curl@7.88.1?arch=amd64",
			want: "pkg:deb/debian/curl@7.88.1",
		},
		{
			name: "keeps version, strips subpath",
			raw:  "pkg:deb/gardenlinux/curl@1.2.3#usr/bin/curl",
			want: "pkg:deb/gardenlinux/curl@1.2.3",
		},
		{
			name: "defaults namespace to debian",
			raw:  "pkg:deb/curl@7.88.1",
			want: "pkg:deb/debian/curl@7.88.1",
		},
		{
			name:    "missing version is an error",
			raw:     "pkg:deb/debian/curl",
			wantErr: true,
		},
		{
			name:    "unparseable PURL is an error",
			raw:     "not-a-purl",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := purl.CanonicalizeVersioned(tc.raw)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestCanonicalize_Idempotent(t *testing.T) {
	t.Parallel()

	inputs := []string{
		"pkg:deb/debian/curl@7.88.1?arch=amd64",
		"pkg:deb/gardenlinux/curl@1.0",
		"pkg:generic/openssl@3.0.0",
		"pkg:golang/github.com/foo/bar@v1.0.0",
	}

	for _, raw := range inputs {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()

			first, err := purl.Canonicalize(raw)
			require.NoError(t, err)

			second, err := purl.Canonicalize(first)
			require.NoError(t, err)

			assert.Equal(t, first, second, "Canonicalize must be idempotent")
		})
	}
}

func TestNamespaceOf(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{
			name: "debian package yields debian",
			raw:  "pkg:deb/debian/curl",
			want: "debian",
		},
		{
			name: "debian package with version yields debian",
			raw:  "pkg:deb/debian/openssl@3.0.0",
			want: "debian",
		},
		{
			name: "gardenlinux package yields gardenlinux",
			raw:  "pkg:deb/gardenlinux/curl",
			want: "gardenlinux",
		},
		{
			name: "deb without namespace defaults to debian",
			raw:  "pkg:deb/curl@7.88.1",
			want: "debian",
		},
		{
			name: "deb with foreign namespace is preserved",
			raw:  "pkg:deb/ubuntu/curl",
			want: "ubuntu",
		},
		{
			name: "non-deb namespace is preserved",
			raw:  "pkg:golang/github.com/foo/bar",
			want: "github.com/foo",
		},
		{
			name: "generic package has no namespace",
			raw:  "pkg:generic/openssl",
			want: "",
		},
		{
			name:    "invalid purl errors",
			raw:     "not-a-purl",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := purl.NamespaceOf(tc.raw)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestConsistency proves that canonicalization is deterministic for the
// expected join key (pkg:deb/debian/<source-name>), regardless of how the
// raw PURL arrives (with version, qualifiers, mixed case, etc.).
func TestConsistency(t *testing.T) {
	t.Parallel()

	variants := []string{
		"pkg:deb/debian/curl",
		"pkg:deb/debian/curl@7.88.1",
		"pkg:deb/debian/curl@7.88.1?arch=amd64",
		"pkg:DEB/DEBIAN/curl@7.88.1",
		"pkg:deb/curl@7.88.1",
		"pkg:/deb/curl@7.88.1",
	}

	const wantKey = "pkg:deb/debian/curl"

	for _, raw := range variants {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()

			got, err := purl.Canonicalize(raw)
			require.NoError(t, err)
			assert.Equal(t, wantKey, got, "all variants must canonicalize to the same join key")
		})
	}
}

func TestNamespaceVariants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{
			name: "debian expands to both namespaces",
			raw:  "pkg:deb/debian/glibc",
			want: []string{"pkg:deb/debian/glibc", "pkg:deb/gardenlinux/glibc"},
		},
		{
			name: "gardenlinux expands to both namespaces",
			raw:  "pkg:deb/gardenlinux/glibc@2.31?arch=amd64",
			want: []string{"pkg:deb/debian/glibc", "pkg:deb/gardenlinux/glibc"},
		},
		{
			name: "unnamespaced deb defaults to debian then expands",
			raw:  "pkg:deb/glibc",
			want: []string{"pkg:deb/debian/glibc", "pkg:deb/gardenlinux/glibc"},
		},
		{
			name: "non-deb namespace stays exact",
			raw:  "pkg:deb/ubuntu/glibc",
			want: []string{"pkg:deb/ubuntu/glibc"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := purl.NamespaceVariants(tc.raw)
			require.NoError(t, err)
			assert.ElementsMatch(t, tc.want, got)
		})
	}
}
