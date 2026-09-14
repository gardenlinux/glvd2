package glmap_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gardenlinux/glvd2/internal/configpath"
	"github.com/gardenlinux/glvd2/internal/cpe"
	"github.com/gardenlinux/glvd2/internal/glmap"
	"github.com/gardenlinux/glvd2/internal/identifier"
	"github.com/gardenlinux/glvd2/internal/ingestion/cvelistv5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeTempConfig writes toml content to a temp file and returns its SafePath.
func writeTempConfig(t *testing.T, content string) configpath.SafePath {
	t.Helper()

	p := filepath.Join(t.TempDir(), "gl_specific_packages.toml")
	require.NoError(t, os.WriteFile(p, []byte(content), 0o644))
	return configpath.SafePath(p)
}

// vp is a shorthand constructor for a vendor/product pair.
func vp(vendor, product string) identifier.VendorProduct {
	return identifier.VendorProduct{Vendor: vendor, Product: product}
}

// wfnMap builds a UniqueWFNMap from vendor/product pairs for CPE lookup inputs.
func wfnMap(t *testing.T, pairs ...identifier.VendorProduct) cpe.UniqueWFNMap {
	t.Helper()

	wfns := make([]cpe.WFN, 0, len(pairs))
	for _, p := range pairs {
		wfns = append(wfns, cpe.WFN{
			Part:    cpe.StringAV("a"),
			Vendor:  cpe.StringAV(p.Vendor),
			Product: cpe.StringAV(p.Product),
		})
	}
	return cpe.NewUniqueWFNMapFrom(wfns)
}

func TestNew_HappyPath(t *testing.T) {
	t.Parallel()

	toml := `
[[rules]]
target_purl     = "pkg:deb/gardenlinux/myspeciallib"
input_purls     = ["pkg:generic/myspeciallib", "pkg:generic/libmyspecial"]
cpes            = [{ vendor = "acme", product = "myspeciallib" }, { vendor = "acme", product = "libmyspecial" }]
vendor_products = [{ vendor = "acme", product = "myspeciallib" }, { vendor = "acme-corp", product = "myspeciallib" }]
package_ids     = [
	{ collection_url = "https://example.com/pkgs", package_name = "myspeciallib" },
	{ collection_url = "https://other.example/pkgs", package_name = "libmyspecial" },
]

[[rules]]
target_purl = "pkg:deb/gardenlinux/anotherlib"
input_purls = ["pkg:generic/anotherlib", "pkg:generic/libanother"]
cpes        = [{ vendor = "other", product = "anotherlib" }]
`
	s, err := glmap.New(writeTempConfig(t, toml))
	require.NoError(t, err)

	tests := []struct {
		name string
		ids  cvelistv5.Identifiers
		want string
	}{
		{
			"rule 1 first purl",
			cvelistv5.Identifiers{PackageURLs: []string{"pkg:generic/myspeciallib"}},
			"pkg:deb/gardenlinux/myspeciallib",
		},
		{
			"rule 1 second purl",
			cvelistv5.Identifiers{PackageURLs: []string{"pkg:generic/libmyspecial"}},
			"pkg:deb/gardenlinux/myspeciallib",
		},
		{
			"rule 1 second cpe",
			cvelistv5.Identifiers{WFNs: wfnMap(t, vp("acme", "libmyspecial"))},
			"pkg:deb/gardenlinux/myspeciallib",
		},
		{
			"rule 1 second vendor_product",
			cvelistv5.Identifiers{
				VendorProductPairs: []identifier.VendorProduct{{Vendor: "acme-corp", Product: "myspeciallib"}},
			},
			"pkg:deb/gardenlinux/myspeciallib",
		},
		{
			"rule 1 second package_id",
			cvelistv5.Identifiers{
				PackageIDs: []cvelistv5.PackageIdentifier{
					{CollectionURL: "https://other.example/pkgs", PackageName: "libmyspecial"},
				},
			},
			"pkg:deb/gardenlinux/myspeciallib",
		},
		{
			"rule 2 second purl",
			cvelistv5.Identifiers{PackageURLs: []string{"pkg:generic/libanother"}},
			"pkg:deb/gardenlinux/anotherlib",
		},
		{
			"rule 2 cpe",
			cvelistv5.Identifiers{WFNs: wfnMap(t, vp("other", "anotherlib"))},
			"pkg:deb/gardenlinux/anotherlib",
		},
		{"miss", cvelistv5.Identifiers{PackageURLs: []string{"pkg:generic/unknown"}}, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, s.Lookup(tc.ids))
		})
	}
}

func TestNew_EmptyConfig(t *testing.T) {
	t.Parallel()

	s, err := glmap.New(writeTempConfig(t, ""))
	require.NoError(t, err)

	assert.Empty(t, s.Lookup(cvelistv5.Identifiers{PackageURLs: []string{"pkg:generic/anything"}}))
}

func TestNew_FileNotFound(t *testing.T) {
	t.Parallel()

	_, err := glmap.New(configpath.SafePath("/tmp/does-not-exist/gl_specific_packages.toml"))
	require.Error(t, err)
}

func TestLookup_NoRulesAndMiss(t *testing.T) {
	t.Parallel()

	s, err := glmap.NewFromRules(nil)
	require.NoError(t, err)

	assert.Empty(t, s.Lookup(cvelistv5.Identifiers{PackageURLs: []string{"pkg:generic/unknown"}}))
}

func TestLookup_MatchPerType(t *testing.T) {
	t.Parallel()

	rules := []glmap.Rule{
		{
			TargetPURL:     "pkg:deb/gardenlinux/liba",
			InputPURLs:     []string{"pkg:generic/liba"},
			CPEs:           []identifier.VendorProduct{{Vendor: "acme", Product: "liba"}},
			VendorProducts: []identifier.VendorProduct{{Vendor: "acme", Product: "liba-vp"}},
			PackageIDs:     []glmap.PackageID{{CollectionURL: "https://example.com", PackageName: "liba"}},
		},
	}

	s, err := glmap.NewFromRules(rules)
	require.NoError(t, err)

	tests := []struct {
		name string
		ids  cvelistv5.Identifiers
	}{
		{"purl", cvelistv5.Identifiers{PackageURLs: []string{"pkg:generic/liba"}}},
		{"cpe", cvelistv5.Identifiers{WFNs: wfnMap(t, vp("acme", "liba"))}},
		{
			"vendor_product",
			cvelistv5.Identifiers{VendorProductPairs: []identifier.VendorProduct{{Vendor: "acme", Product: "liba-vp"}}},
		},
		{
			"package_id",
			cvelistv5.Identifiers{
				PackageIDs: []cvelistv5.PackageIdentifier{{CollectionURL: "https://example.com", PackageName: "liba"}},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, "pkg:deb/gardenlinux/liba", s.Lookup(tc.ids))
		})
	}
}

func TestLookup_PURLCanonicalizedAtLookup(t *testing.T) {
	t.Parallel()

	rules := []glmap.Rule{
		{TargetPURL: "pkg:deb/gardenlinux/mylib", InputPURLs: []string{"pkg:generic/mylib"}},
	}

	s, err := glmap.NewFromRules(rules)
	require.NoError(t, err)

	tests := []struct {
		name string
		purl string
	}{
		{"canonical", "pkg:generic/mylib"},
		{"with version", "pkg:generic/mylib@1.0"},
		{"with qualifiers", "pkg:generic/mylib@1.0?checksum=sha256:abc"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(
				t,
				"pkg:deb/gardenlinux/mylib",
				s.Lookup(cvelistv5.Identifiers{PackageURLs: []string{tc.purl}}),
			)
		})
	}
}

func TestLookup_TargetPURLCanonicalized(t *testing.T) {
	t.Parallel()

	rules := []glmap.Rule{
		{TargetPURL: "pkg:deb/gardenlinux/mylib@1.2.3?arch=amd64", InputPURLs: []string{"pkg:generic/mylib"}},
	}

	s, err := glmap.NewFromRules(rules)
	require.NoError(t, err)

	assert.Equal(
		t,
		"pkg:deb/gardenlinux/mylib",
		s.Lookup(cvelistv5.Identifiers{PackageURLs: []string{"pkg:generic/mylib"}}),
	)
}

func TestLookup_VendorProductCaseInsensitive(t *testing.T) {
	t.Parallel()

	rules := []glmap.Rule{
		{TargetPURL: "pkg:deb/gardenlinux/mylib", CPEs: []identifier.VendorProduct{{Vendor: "acme", Product: "mylib"}}},
	}

	s, err := glmap.NewFromRules(rules)
	require.NoError(t, err)

	tests := []struct {
		name   string
		vendor string
		prod   string
	}{
		{"lower", "acme", "mylib"},
		{"upper vendor", "ACME", "mylib"},
		{"mixed", "Acme", "MyLib"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := s.Lookup(
				cvelistv5.Identifiers{WFNs: wfnMap(t, vp(tc.vendor, tc.prod))},
			)
			assert.Equal(t, "pkg:deb/gardenlinux/mylib", got)
		})
	}
}

func TestLookup_PackageIDCaseInsensitive(t *testing.T) {
	t.Parallel()

	rules := []glmap.Rule{
		{
			TargetPURL: "pkg:deb/gardenlinux/mylib",
			PackageIDs: []glmap.PackageID{{CollectionURL: "https://example.com", PackageName: "MyLib"}},
		},
	}

	s, err := glmap.NewFromRules(rules)
	require.NoError(t, err)

	tests := []struct {
		name string
		pid  cvelistv5.PackageIdentifier
	}{
		{"exact", cvelistv5.PackageIdentifier{CollectionURL: "https://example.com", PackageName: "MyLib"}},
		{"lowered name", cvelistv5.PackageIdentifier{CollectionURL: "https://example.com", PackageName: "mylib"}},
		{"uppered url", cvelistv5.PackageIdentifier{CollectionURL: "https://EXAMPLE.com", PackageName: "mylib"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, "pkg:deb/gardenlinux/mylib",
				s.Lookup(cvelistv5.Identifiers{PackageIDs: []cvelistv5.PackageIdentifier{tc.pid}}))
		})
	}
}

func TestLookup_CPEAndVendorProductDoNotCollide(t *testing.T) {
	t.Parallel()

	// Same vendor/product under both types is allowed and matched independently.
	rules := []glmap.Rule{
		{
			TargetPURL: "pkg:deb/gardenlinux/from-cpe",
			CPEs:       []identifier.VendorProduct{{Vendor: "acme", Product: "lib"}},
		},
		{
			TargetPURL:     "pkg:deb/gardenlinux/from-vp",
			VendorProducts: []identifier.VendorProduct{{Vendor: "acme", Product: "lib"}},
		},
	}

	s, err := glmap.NewFromRules(rules)
	require.NoError(t, err)

	assert.Equal(t, "pkg:deb/gardenlinux/from-cpe",
		s.Lookup(cvelistv5.Identifiers{WFNs: wfnMap(t, vp("acme", "lib"))}))
	assert.Equal(
		t,
		"pkg:deb/gardenlinux/from-vp",
		s.Lookup(
			cvelistv5.Identifiers{VendorProductPairs: []identifier.VendorProduct{{Vendor: "acme", Product: "lib"}}},
		),
	)
}

func TestNewFromRules_Errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		rules []glmap.Rule
	}{
		{
			"empty target_purl",
			[]glmap.Rule{{TargetPURL: "", InputPURLs: []string{"pkg:generic/mylib"}}},
		},
		{
			"no input identifiers",
			[]glmap.Rule{{TargetPURL: "pkg:deb/gardenlinux/mylib"}},
		},
		{
			"invalid target_purl",
			[]glmap.Rule{{TargetPURL: "not-a-valid-purl", InputPURLs: []string{"pkg:generic/mylib"}}},
		},
		{
			"invalid input_purl",
			[]glmap.Rule{{TargetPURL: "pkg:deb/gardenlinux/mylib", InputPURLs: []string{"not-a-valid-purl"}}},
		},
		{
			"duplicate across rules",
			[]glmap.Rule{
				{TargetPURL: "pkg:deb/gardenlinux/mylib", InputPURLs: []string{"pkg:generic/mylib"}},
				{TargetPURL: "pkg:deb/gardenlinux/other", InputPURLs: []string{"pkg:generic/mylib"}},
			},
		},
		{
			"duplicate via canonical purl",
			[]glmap.Rule{
				{TargetPURL: "pkg:deb/gardenlinux/mylib", InputPURLs: []string{"pkg:generic/mylib@1.0"}},
				{TargetPURL: "pkg:deb/gardenlinux/other", InputPURLs: []string{"pkg:generic/mylib@2.0"}},
			},
		},
		{
			"duplicate via case fold",
			[]glmap.Rule{
				{
					TargetPURL: "pkg:deb/gardenlinux/mylib",
					CPEs:       []identifier.VendorProduct{{Vendor: "acme", Product: "mylib"}},
				},
				{
					TargetPURL: "pkg:deb/gardenlinux/other",
					CPEs:       []identifier.VendorProduct{{Vendor: "ACME", Product: "MyLib"}},
				},
			},
		},
		{
			"duplicate within rule",
			[]glmap.Rule{{
				TargetPURL: "pkg:deb/gardenlinux/mylib",
				InputPURLs: []string{"pkg:generic/mylib", "pkg:generic/mylib@1.0"},
			}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := glmap.NewFromRules(tc.rules)
			require.Error(t, err)
		})
	}
}
