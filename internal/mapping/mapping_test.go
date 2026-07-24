package mapping_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/gardenlinux/glvd2/internal/component"
	"github.com/gardenlinux/glvd2/internal/cpe"
	"github.com/gardenlinux/glvd2/internal/ingestion/cvelistv5"
	"github.com/gardenlinux/glvd2/internal/mapping"
	"github.com/gardenlinux/glvd2/internal/repository"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubQuerier implements mapping.AffectedPackageQuerier for tests.
type stubQuerier struct {
	packages []repository.DebianTriageAffectedPackage
	err      error
}

func (s *stubQuerier) ListAffectedDebianPackages(_ context.Context) ([]repository.DebianTriageAffectedPackage, error) {
	return s.packages, s.err
}

// emptyFilterPath returns the path to a TOML filter that discards nothing.
func emptyFilterPath(t *testing.T) component.SafePath {
	t.Helper()

	return writeTempFilter(t, "")
}

// newTestService creates a Service with noop filter configs and a stub querier.
func newTestService(t *testing.T, pkgs []repository.DebianTriageAffectedPackage) *mapping.Service {
	t.Helper()

	s, err := mapping.NewService(&stubQuerier{packages: pkgs}, mapping.WithFilterPaths(
		emptyFilterPath(t),
		emptyFilterPath(t),
		emptyFilterPath(t),
	))
	require.NoError(t, err)
	return s
}

// newTestServiceWithVPFilter creates a Service with a custom vendor-product filter TOML.
func newTestServiceWithVPFilter(
	t *testing.T,
	pkgs []repository.DebianTriageAffectedPackage,
	vpTOML string,
) *mapping.Service {
	t.Helper()

	s, err := mapping.NewService(&stubQuerier{packages: pkgs}, mapping.WithFilterPaths(
		writeTempFilter(t, vpTOML),
		emptyFilterPath(t),
		emptyFilterPath(t),
	))
	require.NoError(t, err)
	return s
}

// newTestServiceWithCPEFilter creates a Service with a custom CPE filter TOML.
func newTestServiceWithCPEFilter(
	t *testing.T,
	pkgs []repository.DebianTriageAffectedPackage,
	cpeTOML string,
) *mapping.Service {
	t.Helper()

	s, err := mapping.NewService(&stubQuerier{packages: pkgs}, mapping.WithFilterPaths(
		emptyFilterPath(t),
		writeTempFilter(t, cpeTOML),
		emptyFilterPath(t),
	))
	require.NoError(t, err)
	return s
}

// newTestServiceWithPkgIDFilter creates a Service with a custom package ID filter TOML.
func newTestServiceWithPkgIDFilter(
	t *testing.T,
	pkgs []repository.DebianTriageAffectedPackage,
	pkgIDTOML string,
) *mapping.Service {
	t.Helper()

	s, err := mapping.NewService(&stubQuerier{packages: pkgs}, mapping.WithFilterPaths(
		emptyFilterPath(t),
		emptyFilterPath(t),
		writeTempFilter(t, pkgIDTOML),
	))
	require.NoError(t, err)
	return s
}

// writeTempFilter writes toml content to a temp file and returns its path.
func writeTempFilter(t *testing.T, content string) component.SafePath {
	t.Helper()

	p := filepath.Join(t.TempDir(), "filter.toml")
	require.NoError(t, os.WriteFile(p, []byte(content), 0o644))
	return component.SafePath(p)
}

func TestNewService_MissingFilterFiles(t *testing.T) {
	t.Parallel()

	nonexistent := component.SafePath("/tmp/cacce6ce-c7ad-44f5-98e9-4c053be6be20/nonexistent_filter.toml")
	valid := emptyFilterPath(t)

	tests := []struct {
		name string
		vp   component.SafePath
		cpe  component.SafePath
		pkg  component.SafePath
	}{
		{
			name: "missing vendor-product filter",
			vp:   nonexistent,
			cpe:  valid,
			pkg:  valid,
		},
		{
			name: "missing CPE filter",
			vp:   valid,
			cpe:  nonexistent,
			pkg:  valid,
		},
		{
			name: "missing package ID filter",
			vp:   valid,
			cpe:  valid,
			pkg:  nonexistent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := mapping.NewService(&stubQuerier{}, mapping.WithFilterPaths(tt.vp, tt.cpe, tt.pkg))
			require.Error(t, err)
		})
	}
}

func TestAnalyze_MatchesVendorProductPairs(t *testing.T) {
	t.Parallel()

	pkgs := []repository.DebianTriageAffectedPackage{
		{CVEID: "CVE-2026-0001", PackageName: "curl"},
		{CVEID: "CVE-2026-0001", PackageName: "libcurl"},
	}

	idsForCVEs := cvelistv5.IDsForCVEs{
		"CVE-2026-0001": &cvelistv5.Identifiers{
			VendorProductPairs: []component.Pair{
				{Vendor: "curl", Product: "curl"},
			},
		},
	}

	s := newTestService(t, pkgs)
	result, pkgIndex, err := s.Analyze(context.Background(), idsForCVEs)
	require.NoError(t, err)

	vpID := `"curl":"curl"`
	assert.Equal(t, 1, result.VendorProductPairs[vpID]["curl"])
	assert.Equal(t, 1, result.VendorProductPairs[vpID]["libcurl"])

	assert.Contains(t, pkgIndex["curl"].VendorProductIDs, vpID)
	assert.Contains(t, pkgIndex["libcurl"].VendorProductIDs, vpID)

	// No cross-contamination into other identifier types.
	assert.Empty(t, result.CPEs)
	assert.Empty(t, result.PackageIDs)
	assert.Empty(t, result.PackageURLs)
}

func TestAnalyze_MatchesCPEs(t *testing.T) {
	t.Parallel()

	pkgs := []repository.DebianTriageAffectedPackage{
		{CVEID: "CVE-2026-0002", PackageName: "openssl"},
	}

	wfnMap := cpe.NewUniqueWFNMapFrom([]cpe.WFN{
		{
			Part:    cpe.StringAV("a"),
			Vendor:  cpe.StringAV("openssl"),
			Product: cpe.StringAV("openssl"),
		},
	})

	idsForCVEs := cvelistv5.IDsForCVEs{
		"CVE-2026-0002": &cvelistv5.Identifiers{
			WFNs: wfnMap,
		},
	}

	s := newTestService(t, pkgs)
	result, pkgIndex, err := s.Analyze(context.Background(), idsForCVEs)
	require.NoError(t, err)

	expectedCPE := "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"
	assert.Equal(t, 1, result.CPEs[expectedCPE]["openssl"])
	assert.Contains(t, pkgIndex["openssl"].CPEs, expectedCPE)

	// No cross-contamination into other identifier types.
	assert.Empty(t, result.VendorProductPairs)
	assert.Empty(t, result.PackageIDs)
	assert.Empty(t, result.PackageURLs)
}

func TestAnalyze_MatchesPackageIDs(t *testing.T) {
	t.Parallel()

	pkgs := []repository.DebianTriageAffectedPackage{
		{CVEID: "CVE-2026-0003", PackageName: "vim"},
	}

	idsForCVEs := cvelistv5.IDsForCVEs{
		"CVE-2026-0003": &cvelistv5.Identifiers{
			PackageIDs: []cvelistv5.PackageIdentifier{
				{CollectionURL: "https://packages.debian.org/", PackageName: "vim"},
			},
		},
	}

	s := newTestService(t, pkgs)
	result, pkgIndex, err := s.Analyze(context.Background(), idsForCVEs)
	require.NoError(t, err)

	pIDStr := `"https://packages.debian.org/":"vim"`
	assert.Equal(t, 1, result.PackageIDs[pIDStr]["vim"])
	assert.Contains(t, pkgIndex["vim"].PackageIDs, pIDStr)

	// No cross-contamination into other identifier types.
	assert.Empty(t, result.VendorProductPairs)
	assert.Empty(t, result.CPEs)
	assert.Empty(t, result.PackageURLs)
}

func TestAnalyze_MatchesPackageURLs(t *testing.T) {
	t.Parallel()

	pkgs := []repository.DebianTriageAffectedPackage{
		{CVEID: "CVE-2026-0004", PackageName: "glibc"},
	}

	idsForCVEs := cvelistv5.IDsForCVEs{
		"CVE-2026-0004": &cvelistv5.Identifiers{
			PackageURLs: []string{"pkg:deb/debian/glibc"},
		},
	}

	s := newTestService(t, pkgs)
	result, pkgIndex, err := s.Analyze(context.Background(), idsForCVEs)
	require.NoError(t, err)

	purl := "pkg:deb/debian/glibc"
	assert.Equal(t, 1, result.PackageURLs[purl]["glibc"])
	assert.Contains(t, pkgIndex["glibc"].PackageURLs, purl)

	// No cross-contamination into other identifier types.
	assert.Empty(t, result.VendorProductPairs)
	assert.Empty(t, result.CPEs)
	assert.Empty(t, result.PackageIDs)
}

func TestAnalyze_FiltersVendorProduct(t *testing.T) {
	t.Parallel()

	pkgs := []repository.DebianTriageAffectedPackage{
		{CVEID: "CVE-2026-0010", PackageName: "curl"},
	}

	idsForCVEs := cvelistv5.IDsForCVEs{
		"CVE-2026-0010": &cvelistv5.Identifiers{
			VendorProductPairs: []component.Pair{
				{Vendor: "oracle", Product: "database"},
				{Vendor: "curl", Product: "curl"},
			},
		},
	}

	vpTOML := `
[[rules]]
groups = ["oracle"]
discard_all = true
`
	s := newTestServiceWithVPFilter(t, pkgs, vpTOML)
	result, _, err := s.Analyze(context.Background(), idsForCVEs)
	require.NoError(t, err)

	oracleID := `"oracle":"database"`
	assert.Empty(t, result.VendorProductPairs[oracleID])

	curlID := `"curl":"curl"`
	assert.Equal(t, 1, result.VendorProductPairs[curlID]["curl"])
}

func TestAnalyze_FiltersCPE(t *testing.T) {
	t.Parallel()

	pkgs := []repository.DebianTriageAffectedPackage{
		{CVEID: "CVE-2026-0011", PackageName: "vim"},
	}

	wfnMap := cpe.NewUniqueWFNMapFrom([]cpe.WFN{
		{Part: cpe.StringAV("a"), Vendor: cpe.StringAV("oracle"), Product: cpe.StringAV("jdk")},
		{Part: cpe.StringAV("a"), Vendor: cpe.StringAV("vim"), Product: cpe.StringAV("vim")},
	})

	idsForCVEs := cvelistv5.IDsForCVEs{
		"CVE-2026-0011": &cvelistv5.Identifiers{
			WFNs: wfnMap,
		},
	}

	cpeTOML := `
[[rules]]
groups = ["oracle"]
discard_all = true
`
	s := newTestServiceWithCPEFilter(t, pkgs, cpeTOML)
	result, pkgIndex, err := s.Analyze(context.Background(), idsForCVEs)
	require.NoError(t, err)

	expectedCPE := "cpe:2.3:a:vim:vim:*:*:*:*:*:*:*:*"
	discardedCPE := "cpe:2.3:a:oracle:jdk:*:*:*:*:*:*:*:*"

	assert.Len(t, result.CPEs, 1)
	assert.Equal(t, 1, result.CPEs[expectedCPE]["vim"])
	assert.Empty(t, result.CPEs[discardedCPE])

	assert.Contains(t, pkgIndex["vim"].CPEs, expectedCPE)
	assert.NotContains(t, pkgIndex["vim"].CPEs, discardedCPE)
}

func TestAnalyze_FiltersPackageID(t *testing.T) {
	t.Parallel()

	pkgs := []repository.DebianTriageAffectedPackage{
		{CVEID: "CVE-2026-0012", PackageName: "curl"},
	}

	idsForCVEs := cvelistv5.IDsForCVEs{
		"CVE-2026-0012": &cvelistv5.Identifiers{
			PackageIDs: []cvelistv5.PackageIdentifier{
				{CollectionURL: "https://example.com/unwanted/", PackageName: "curl"},
				{CollectionURL: "https://packages.debian.org/", PackageName: "curl"},
			},
		},
	}

	pkgIDTOML := `
[[rules]]
groups = ["https://example.com/unwanted/"]
discard_all = true
`
	s := newTestServiceWithPkgIDFilter(t, pkgs, pkgIDTOML)
	result, pkgIndex, err := s.Analyze(context.Background(), idsForCVEs)
	require.NoError(t, err)

	keptID := `"https://packages.debian.org/":"curl"`
	discardedID := `"https://example.com/unwanted/":"curl"`

	assert.Len(t, result.PackageIDs, 1)
	assert.Equal(t, 1, result.PackageIDs[keptID]["curl"])
	assert.Empty(t, result.PackageIDs[discardedID])

	assert.Contains(t, pkgIndex["curl"].PackageIDs, keptID)
	assert.NotContains(t, pkgIndex["curl"].PackageIDs, discardedID)
}

func TestAnalyze_SpecialRedHatProductsPackageIDFiltering(t *testing.T) {
	t.Parallel()

	pkgs := []repository.DebianTriageAffectedPackage{
		{CVEID: "CVE-2026-0020", PackageName: "curl"},
	}

	idsForCVEs := cvelistv5.IDsForCVEs{
		"CVE-2026-0020": &cvelistv5.Identifiers{
			PackageIDs: []cvelistv5.PackageIdentifier{
				{
					CollectionURL: "https://access.redhat.com/downloads/content/package-browser/",
					PackageName:   "curl",
				},
				{
					CollectionURL: "https://access.redhat.com/downloads/content/package-browser/",
					PackageName:   "Red Hat Enterprise Linux 9",
				},
				{
					CollectionURL: "https://packages.debian.org/",
					PackageName:   "something-unrelated",
				},
			},
		},
	}

	s := newTestService(t, pkgs)
	result, pkgIndex, err := s.Analyze(context.Background(), idsForCVEs)
	require.NoError(t, err)

	keptRedHat := `"https://access.redhat.com/downloads/content/package-browser/":"curl"`
	keptDebian := `"https://packages.debian.org/":"something-unrelated"`
	discardedRedHat := `"https://access.redhat.com/downloads/content/package-browser/":"Red Hat Enterprise Linux 9"`

	// Two entries kept: the Red Hat one containing "curl" and the Debian one.
	assert.Len(t, result.PackageIDs, 2)
	assert.Equal(t, 1, result.PackageIDs[keptRedHat]["curl"])
	assert.Equal(t, 1, result.PackageIDs[keptDebian]["curl"])
	assert.Empty(t, result.PackageIDs[discardedRedHat])

	assert.Contains(t, pkgIndex["curl"].PackageIDs, keptRedHat)
	assert.Contains(t, pkgIndex["curl"].PackageIDs, keptDebian)
	assert.NotContains(t, pkgIndex["curl"].PackageIDs, discardedRedHat)
}

func TestAnalyze_NoCVEIDsFound_Continues(t *testing.T) {
	t.Parallel()

	pkgs := []repository.DebianTriageAffectedPackage{
		{CVEID: "CVE-2026-9999", PackageName: "unknown-pkg"},
		{CVEID: "CVE-2026-0001", PackageName: "curl"},
	}

	idsForCVEs := cvelistv5.IDsForCVEs{
		"CVE-2026-0001": &cvelistv5.Identifiers{
			VendorProductPairs: []component.Pair{
				{Vendor: "curl", Product: "curl"},
			},
		},
	}

	s := newTestService(t, pkgs)
	result, pkgIndex, err := s.Analyze(context.Background(), idsForCVEs)
	require.NoError(t, err)

	vpID := `"curl":"curl"`
	assert.Equal(t, 1, result.VendorProductPairs[vpID]["curl"])

	// The unknown package should not appear in results or index.
	assert.Empty(t, result.VendorProductPairs[vpID]["unknown-pkg"])
	assert.Empty(t, pkgIndex["unknown-pkg"])

	// The valid package should be in the index.
	assert.Contains(t, pkgIndex["curl"].VendorProductIDs, vpID)
}

func TestAnalyze_QuerierError(t *testing.T) {
	t.Parallel()

	expectedErr := errors.New("db connection lost")
	s, err := mapping.NewService(&stubQuerier{err: expectedErr}, mapping.WithFilterPaths(
		emptyFilterPath(t),
		emptyFilterPath(t),
		emptyFilterPath(t),
	))
	require.NoError(t, err)

	_, _, err = s.Analyze(context.Background(), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, expectedErr)
}

func TestAnalyze_EmptyInputs(t *testing.T) {
	t.Parallel()

	s := newTestService(t, nil)
	result, pkgIndex, err := s.Analyze(context.Background(), cvelistv5.IDsForCVEs{})
	require.NoError(t, err)

	assert.Empty(t, result.VendorProductPairs)
	assert.Empty(t, result.CPEs)
	assert.Empty(t, result.PackageIDs)
	assert.Empty(t, result.PackageURLs)
	assert.Empty(t, pkgIndex)
}

func TestAnalyze_MultipleOccurrencesIncrementCount(t *testing.T) {
	t.Parallel()

	// Four CVEs affect "apache2"; one also affects "apache2-utils".
	// Each CVE provides different subsets of identifiers to produce asymmetric counts
	// where every identifier type reaches > 1 for "apache2".
	pkgs := []repository.DebianTriageAffectedPackage{
		{CVEID: "CVE-2026-0050", PackageName: "apache2"},
		{CVEID: "CVE-2026-0050", PackageName: "apache2-utils"},
		{CVEID: "CVE-2026-0051", PackageName: "apache2"},
		{CVEID: "CVE-2026-0052", PackageName: "apache2"},
		{CVEID: "CVE-2026-0053", PackageName: "apache2"},
	}

	idsForCVEs := cvelistv5.IDsForCVEs{
		// CVE-0050: all four identifier types
		"CVE-2026-0050": &cvelistv5.Identifiers{
			VendorProductPairs: []component.Pair{
				{Vendor: "apache", Product: "http_server"},
			},
			WFNs: cpe.NewUniqueWFNMapFrom([]cpe.WFN{
				{Part: cpe.StringAV("a"), Vendor: cpe.StringAV("apache"), Product: cpe.StringAV("http_server")},
			}),
			PackageIDs: []cvelistv5.PackageIdentifier{
				{CollectionURL: "https://packages.debian.org/", PackageName: "apache2"},
			},
			PackageURLs: []string{"pkg:deb/debian/apache2"},
		},
		// CVE-0051: all four identifier types
		"CVE-2026-0051": &cvelistv5.Identifiers{
			VendorProductPairs: []component.Pair{
				{Vendor: "apache", Product: "http_server"},
			},
			WFNs: cpe.NewUniqueWFNMapFrom([]cpe.WFN{
				{Part: cpe.StringAV("a"), Vendor: cpe.StringAV("apache"), Product: cpe.StringAV("http_server")},
			}),
			PackageIDs: []cvelistv5.PackageIdentifier{
				{CollectionURL: "https://packages.debian.org/", PackageName: "apache2"},
			},
			PackageURLs: []string{"pkg:deb/debian/apache2"},
		},
		// CVE-0052: VP + CPE only
		"CVE-2026-0052": &cvelistv5.Identifiers{
			VendorProductPairs: []component.Pair{
				{Vendor: "apache", Product: "http_server"},
			},
			WFNs: cpe.NewUniqueWFNMapFrom([]cpe.WFN{
				{Part: cpe.StringAV("a"), Vendor: cpe.StringAV("apache"), Product: cpe.StringAV("http_server")},
			}),
		},
		// CVE-0053: VP only
		"CVE-2026-0053": &cvelistv5.Identifiers{
			VendorProductPairs: []component.Pair{
				{Vendor: "apache", Product: "http_server"},
			},
		},
	}

	s := newTestService(t, pkgs)
	result, _, err := s.Analyze(context.Background(), idsForCVEs)
	require.NoError(t, err)

	vpID := `"apache":"http_server"`
	cpeStr := "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
	pIDStr := `"https://packages.debian.org/":"apache2"`
	purl := "pkg:deb/debian/apache2"

	// "apache2" appears in 4 CVEs with VP, 3 with CPE, 2 with package ID, 2 with PURL.
	assert.Equal(t, 4, result.VendorProductPairs[vpID]["apache2"])
	assert.Equal(t, 3, result.CPEs[cpeStr]["apache2"])
	assert.Equal(t, 2, result.PackageIDs[pIDStr]["apache2"])
	assert.Equal(t, 2, result.PackageURLs[purl]["apache2"])

	// "apache2-utils" only appears in CVE-0050, so all its counters are 1.
	assert.Equal(t, 1, result.VendorProductPairs[vpID]["apache2-utils"])
	assert.Equal(t, 1, result.CPEs[cpeStr]["apache2-utils"])
	assert.Equal(t, 1, result.PackageIDs[pIDStr]["apache2-utils"])
	assert.Equal(t, 1, result.PackageURLs[purl]["apache2-utils"])
}

func TestAnalyze_MultipleFiltersActive(t *testing.T) {
	t.Parallel()

	pkgs := []repository.DebianTriageAffectedPackage{
		{CVEID: "CVE-2026-0070", PackageName: "libfoo"},
	}

	idsForCVEs := cvelistv5.IDsForCVEs{
		"CVE-2026-0070": &cvelistv5.Identifiers{
			VendorProductPairs: []component.Pair{
				{Vendor: "oracle", Product: "database"},
				{Vendor: "libfoo", Product: "libfoo"},
			},
			WFNs: cpe.NewUniqueWFNMapFrom([]cpe.WFN{
				{Part: cpe.StringAV("a"), Vendor: cpe.StringAV("microsoft"), Product: cpe.StringAV("windows")},
				{Part: cpe.StringAV("a"), Vendor: cpe.StringAV("libfoo"), Product: cpe.StringAV("libfoo")},
			}),
			PackageIDs: []cvelistv5.PackageIdentifier{
				{CollectionURL: "https://unwanted.example.com/", PackageName: "libfoo"},
				{CollectionURL: "https://packages.debian.org/", PackageName: "libfoo"},
			},
			PackageURLs: []string{"pkg:deb/debian/libfoo"},
		},
	}

	vpTOML := `
[[rules]]
groups = ["oracle"]
discard_all = true
`
	cpeTOML := `
[[rules]]
groups = ["microsoft"]
discard_all = true
`
	pkgIDTOML := `
[[rules]]
groups = ["https://unwanted.example.com/"]
discard_all = true
`

	s, err := mapping.NewService(&stubQuerier{packages: pkgs}, mapping.WithFilterPaths(
		writeTempFilter(t, vpTOML),
		writeTempFilter(t, cpeTOML),
		writeTempFilter(t, pkgIDTOML),
	))
	require.NoError(t, err)

	result, pkgIndex, err := s.Analyze(context.Background(), idsForCVEs)
	require.NoError(t, err)

	// VP: oracle:database discarded, libfoo:libfoo kept.
	discardedVP := `"oracle":"database"`
	keptVP := `"libfoo":"libfoo"`
	assert.Empty(t, result.VendorProductPairs[discardedVP])
	assert.Equal(t, 1, result.VendorProductPairs[keptVP]["libfoo"])

	// CPE: microsoft:windows discarded, libfoo:libfoo kept.
	discardedCPE := "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*"
	keptCPE := "cpe:2.3:a:libfoo:libfoo:*:*:*:*:*:*:*:*"
	assert.Empty(t, result.CPEs[discardedCPE])
	assert.Equal(t, 1, result.CPEs[keptCPE]["libfoo"])

	// PackageID: unwanted discarded, Debian kept.
	discardedPkgID := `"https://unwanted.example.com/":"libfoo"`
	keptPkgID := `"https://packages.debian.org/":"libfoo"`
	assert.Empty(t, result.PackageIDs[discardedPkgID])
	assert.Equal(t, 1, result.PackageIDs[keptPkgID]["libfoo"])

	// PURL: unfiltered, always kept.
	assert.Equal(t, 1, result.PackageURLs["pkg:deb/debian/libfoo"]["libfoo"])

	// PackageIdentifierIndex only contains surviving identifiers.
	assert.Contains(t, pkgIndex["libfoo"].VendorProductIDs, keptVP)
	assert.NotContains(t, pkgIndex["libfoo"].VendorProductIDs, discardedVP)
	assert.Contains(t, pkgIndex["libfoo"].CPEs, keptCPE)
	assert.NotContains(t, pkgIndex["libfoo"].CPEs, discardedCPE)
	assert.Contains(t, pkgIndex["libfoo"].PackageIDs, keptPkgID)
	assert.NotContains(t, pkgIndex["libfoo"].PackageIDs, discardedPkgID)
	assert.Contains(t, pkgIndex["libfoo"].PackageURLs, "pkg:deb/debian/libfoo")
}

func TestAnalyze_PackageIndexIdentifiersAreUnique(t *testing.T) {
	t.Parallel()

	pkgs := []repository.DebianTriageAffectedPackage{
		{CVEID: "CVE-2026-0090", PackageName: "nginx"},
		{CVEID: "CVE-2026-0091", PackageName: "nginx"},
	}

	// Both CVEs share identical identifiers.
	sharedIDs := &cvelistv5.Identifiers{
		VendorProductPairs: []component.Pair{
			{Vendor: "nginx", Product: "nginx"},
		},
		WFNs: cpe.NewUniqueWFNMapFrom([]cpe.WFN{
			{Part: cpe.StringAV("a"), Vendor: cpe.StringAV("nginx"), Product: cpe.StringAV("nginx")},
		}),
		PackageIDs: []cvelistv5.PackageIdentifier{
			{CollectionURL: "https://packages.debian.org/", PackageName: "nginx"},
		},
		PackageURLs: []string{"pkg:deb/debian/nginx"},
	}

	idsForCVEs := cvelistv5.IDsForCVEs{
		"CVE-2026-0090": sharedIDs,
		"CVE-2026-0091": sharedIDs,
	}

	s := newTestService(t, pkgs)
	result, pkgIndex, err := s.Analyze(context.Background(), idsForCVEs)
	require.NoError(t, err)

	vpID := `"nginx":"nginx"`
	cpeStr := "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"
	pkgIDStr := `"https://packages.debian.org/":"nginx"`
	purl := "pkg:deb/debian/nginx"

	// Counters should be 2 (one per CVE).
	assert.Equal(t, 2, result.VendorProductPairs[vpID]["nginx"])
	assert.Equal(t, 2, result.CPEs[cpeStr]["nginx"])
	assert.Equal(t, 2, result.PackageIDs[pkgIDStr]["nginx"])
	assert.Equal(t, 2, result.PackageURLs[purl]["nginx"])

	// Index entries must be deduplicated — length 1 despite two CVEs contributing.
	assert.Len(t, pkgIndex["nginx"].VendorProductIDs, 1)
	assert.Len(t, pkgIndex["nginx"].CPEs, 1)
	assert.Len(t, pkgIndex["nginx"].PackageIDs, 1)
	assert.Len(t, pkgIndex["nginx"].PackageURLs, 1)
}

func TestAnalyze_SkipsCPEsWithNonStringVendorOrProduct(t *testing.T) {
	t.Parallel()

	pkgs := []repository.DebianTriageAffectedPackage{
		{CVEID: "CVE-2026-0060", PackageName: "somelib"},
	}

	wfnMap := cpe.NewUniqueWFNMapFrom([]cpe.WFN{
		{Part: cpe.StringAV("a"), Vendor: cpe.Any(), Product: cpe.StringAV("somelib")},
		{Part: cpe.StringAV("a"), Vendor: cpe.StringAV("vendor"), Product: cpe.NA()},
		{Part: cpe.StringAV("a"), Vendor: cpe.StringAV("acme"), Product: cpe.StringAV("somelib")},
	})

	idsForCVEs := cvelistv5.IDsForCVEs{
		"CVE-2026-0060": &cvelistv5.Identifiers{
			WFNs: wfnMap,
		},
	}

	s := newTestService(t, pkgs)
	result, pkgIndex, err := s.Analyze(context.Background(), idsForCVEs)
	require.NoError(t, err)

	expectedCPE := "cpe:2.3:a:acme:somelib:*:*:*:*:*:*:*:*"

	assert.Len(t, result.CPEs, 1)
	assert.Equal(t, 1, result.CPEs[expectedCPE]["somelib"])
	assert.Contains(t, pkgIndex["somelib"].CPEs, expectedCPE)
	assert.Len(t, pkgIndex["somelib"].CPEs, 1)
}
