package filter_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gardenlinux/glvd2/internal/configpath"
	"github.com/gardenlinux/glvd2/internal/debmap/filter"
	"github.com/gardenlinux/glvd2/internal/identifier"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRules_ShouldDiscard(t *testing.T) {
	t.Parallel()

	rawRules := `
[[rules]]
groups = ["oracle"]
discard_all = true

[[rules]]
groups = ["linux"]
prefix_filters = ["util-linux","security"]

[[rules]]
groups = ["red hat"]
contains_filters = ["rhel"]

[[rules]]
groups = ["siemens"]
suffix_filters = ["engine"]

[[rules]]
groups = ["fedora"]
equals = ["fedora"]

[[rules]]
groups = ["*"]
prefix_filters = ["penguin"]
suffix_filters = ["zzz"]
contains_filters = ["abcd"]
equals = ["ms-teams"]
`
	path := filepath.Join(t.TempDir(), "filter.toml")
	require.NoError(t, os.WriteFile(path, []byte(rawRules), 0o644))

	r, err := filter.New(configpath.SafePath(path))
	require.NoError(t, err)

	tests := []struct {
		name  string
		pairs []identifier.VendorProduct
		want  bool
	}{
		{
			name: "discard_vendor rule should discard",
			pairs: []identifier.VendorProduct{
				{Vendor: "oracle", Product: "some product"},
				{Vendor: "oracle", Product: "another product"},
			},
			want: true,
		},
		{
			name: "prefix filter should match",
			pairs: []identifier.VendorProduct{
				{Vendor: "linux", Product: "util-linux"},
				{Vendor: "linux", Product: "util-linux8"},
				{Vendor: "linux", Product: "util-linux 8 3"},
				{Vendor: "linux", Product: "security manager"},
			},
			want: true,
		},
		{
			name: "prefix filter should not match",
			pairs: []identifier.VendorProduct{
				{Vendor: "linux", Product: "util"},
				{Vendor: "linux", Product: "utillinux"},
				{Vendor: "linux", Product: "util-linu"},
				{Vendor: "linux", Product: "secur"},
				{Vendor: "linux", Product: "secure"},
			},
			want: false,
		},
		{
			name: "wildcard prefix filter should match",
			pairs: []identifier.VendorProduct{
				{Vendor: "linux", Product: "penguin tux"},
			},
			want: true,
		},
		{
			name: "contains filter should match",
			pairs: []identifier.VendorProduct{
				{Vendor: "red hat", Product: "rhel 9 container engine"},
				{Vendor: "red hat", Product: "manager for rhel"},
				{Vendor: "red hat", Product: "security module for rhel 9"},
				{Vendor: "red hat", Product: "security module for rhelict 9"},
			},
			want: true,
		},
		{
			name: "contains filter should not match",
			pairs: []identifier.VendorProduct{
				{Vendor: "red hat", Product: "some product from red hat"},
				{Vendor: "red hat", Product: "rhe red hat"},
			},
			want: false,
		},
		{
			name: "wildcard contains filter should match",
			pairs: []identifier.VendorProduct{
				{Vendor: "red hat", Product: "aabcde"},
			},
			want: true,
		},
		{
			name: "suffix filter should match",
			pairs: []identifier.VendorProduct{
				{Vendor: "siemens", Product: "container engine"},
				{Vendor: "siemens", Product: "manager-engine"},
				{Vendor: "siemens", Product: "engine"},
				{Vendor: "siemens", Product: "anotherengine"},
			},
			want: true,
		},
		{
			name: "suffix filter should not match",
			pairs: []identifier.VendorProduct{
				{Vendor: "siemens", Product: "engine machine"},
				{Vendor: "siemens", Product: "enginemeter"},
				{Vendor: "siemens", Product: "engin"},
			},
			want: false,
		},
		{
			name: "wildcard suffix filter should match",
			pairs: []identifier.VendorProduct{
				{Vendor: "siemens", Product: "somethingzzz"},
			},
			want: true,
		},
		{
			name: "equal filter should match",
			pairs: []identifier.VendorProduct{
				{Vendor: "fedora", Product: "fedora"},
			},
			want: true,
		},
		{
			name: "equal filter should not match",
			pairs: []identifier.VendorProduct{
				{Vendor: "fedora", Product: "smarttool"},
				{Vendor: "fedora", Product: "fedora smarttool"},
				{Vendor: "fedora", Product: "smarttool fedora"},
				{Vendor: "fedora", Product: "xfedorax"},
			},
			want: false,
		},
		{
			name: "wildcard equal filter should match",
			pairs: []identifier.VendorProduct{
				{Vendor: "microsoft", Product: "ms-teams"},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			for _, p := range tt.pairs {
				got := r.ShouldDiscard(p.Vendor, p.Product)
				assert.Equal(t, tt.want, got, "test value: %s", p.String())
			}
		})
	}
}

func TestNew_InvalidConfigPath(t *testing.T) {
	t.Parallel()

	const nonExistent = "/nonexistent/f831ea16-b148-4225-9f99-6382b0672905/path.toml"
	_, err := filter.New(nonExistent)
	assert.Error(t, err)
}

// TestNew_ProjectFilterConfig verifies the actual project config files can be parsed.
func TestNew_ProjectFilterConfig(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "..", "config", "vendor_product_filter.toml")
	r, err := filter.New(configpath.SafePath(path))
	require.NoError(t, err)

	t.Run("smoke-tests where ShouldDiscard should discard", func(t *testing.T) {
		t.Parallel()

		shouldDiscard := []identifier.VendorProduct{
			{Vendor: "red hat", Product: "red hat enterprise linux"},
			{Vendor: "red hat, inc.", Product: "red hat enterprise linux"},
			{Vendor: "red hat, inc.", Product: "openshift container platform"},
			{Vendor: "suse", Product: "suse linux enterprise"},
			{Vendor: "siemens", Product: "simatic s7"},
			{Vendor: "fedoraproject", Product: "fedora"},
			{Vendor: "fedora", Product: "fedora linux"},
		}

		for _, pair := range shouldDiscard {
			assert.True(t, r.ShouldDiscard(pair.Vendor, pair.Product), "test value: %s", pair.String())
		}
	})

	t.Run("smoke-tests where ShouldDiscard should not discard", func(t *testing.T) {
		t.Parallel()

		shouldNotDiscard := []identifier.VendorProduct{
			{Vendor: "", Product: ""},
			{Vendor: "debian", Product: "dpkg"},
			{Vendor: "red hat", Product: "ansible"},
			{Vendor: "curl", Product: "curl"},
			{Vendor: "containerd", Product: "containerd"},
			{Vendor: "opencontainers", Product: "runc"},
			{Vendor: "the dracut project", Product: "dracut"},
			{Vendor: "gnu", Product: "glibc"},
			{Vendor: "gnutls", Product: "gnutls"},
			{Vendor: "libxml2", Product: "libxml2"},
			{Vendor: "linux", Product: "util-linux"},
			{Vendor: "jqlang", Product: "jq"},
			{Vendor: "sudo project", Product: "sudo"},
			{Vendor: "openssl", Product: "openssl"},
			{Vendor: "openbsd", Product: "openssh"},
			{Vendor: "vim", Product: "vim"},
			{Vendor: "golang", Product: "go"},
			{Vendor: "systemd", Product: "systemd"},
		}

		for _, pair := range shouldNotDiscard {
			assert.False(t, r.ShouldDiscard(pair.Vendor, pair.Product), "test value: %s", pair.String())
		}
	})
}

func TestNewFromRules_EmptyRules(t *testing.T) {
	t.Parallel()

	r := filter.NewFromRules(nil)
	assert.False(t, r.ShouldDiscard("any", "value"))
}
