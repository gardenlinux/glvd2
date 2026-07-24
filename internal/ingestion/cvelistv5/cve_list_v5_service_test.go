package cvelistv5_test

import (
	"context"
	"testing"

	"github.com/gardenlinux/glvd2/internal/component"
	"github.com/gardenlinux/glvd2/internal/config"
	"github.com/gardenlinux/glvd2/internal/cpe"
	"github.com/gardenlinux/glvd2/internal/ingestion/cvelistv5"
	"github.com/gardenlinux/glvd2/internal/model/cve_v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPackageIdentifier_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    cvelistv5.PackageIdentifier
		expected string
	}{
		{
			name:     "normal values",
			input:    cvelistv5.PackageIdentifier{CollectionURL: "https://packages.debian.org/", PackageName: "vim"},
			expected: `"https://packages.debian.org/":"vim"`,
		},
		{
			name:     "empty values",
			input:    cvelistv5.PackageIdentifier{CollectionURL: "", PackageName: ""},
			expected: `"":""`,
		},
		{
			name:     "values with quotes",
			input:    cvelistv5.PackageIdentifier{CollectionURL: `has"quote`, PackageName: `also"here`},
			expected: `"has\"quote":"also\"here"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.input.String())
		})
	}
}

func newService(dir string) *cvelistv5.Service {
	return cvelistv5.NewService(&config.AppConfig{
		CVEListV5SubRepoPath: "testdata/" + dir,
	})
}

func createWFN(vendor, product string) cpe.WFN {
	return cpe.WFN{Part: cpe.StringAV("a"), Vendor: cpe.StringAV(vendor), Product: cpe.StringAV(product)}
}

func TestGetIDsForCVEs_ValidFixtures(t *testing.T) {
	t.Parallel()

	idsForCVEs, err := newService("valid").GetIDsForCVEs(t.Context())
	require.NoError(t, err)
	require.Len(t, idsForCVEs, 4, "should have parsed all 4 CVE files")

	t.Run("AllIdentifiersExtracted", func(t *testing.T) {
		t.Parallel()

		ids := idsForCVEs["CVE-2026-0001"]
		require.NotNil(t, ids, "CVE-2026-0001 should be present")

		assert.Len(t, ids.VendorProductPairs, 1)
		assert.Equal(t, "curl", ids.VendorProductPairs[0].Vendor)
		assert.Equal(t, "curl", ids.VendorProductPairs[0].Product)

		assert.Len(t, ids.WFNs, 1)
		wfn := createWFN("curl", "curl")
		assert.True(t, ids.WFNs.Contains(wfn), "contains the right WFN")

		assert.Len(t, ids.PackageIDs, 1)
		assert.Equal(t, "https://packages.debian.org/", ids.PackageIDs[0].CollectionURL)
		assert.Equal(t, "curl", ids.PackageIDs[0].PackageName)

		assert.Equal(t, []string{"pkg:deb/debian/curl"}, ids.PackageURLs)
	})

	t.Run("CPEApplicabilityExtracted", func(t *testing.T) {
		t.Parallel()

		ids := idsForCVEs["CVE-2026-0002"]
		require.NotNil(t, ids, "CVE-2026-0002 should be present")

		assert.Empty(t, ids.VendorProductPairs)
		assert.Empty(t, ids.PackageIDs)
		assert.Empty(t, ids.PackageURLs)

		assert.Len(t, ids.WFNs, 1, "two openssl CPEs normalize to same vendor:product")
		wfn := createWFN("openssl", "openssl")
		assert.True(t, ids.WFNs.Contains(wfn), "contains the right WFN")
	})

	t.Run("ADPContainerMerged", func(t *testing.T) {
		t.Parallel()

		ids := idsForCVEs["CVE-2026-0003"]
		require.NotNil(t, ids, "CVE-2026-0003 should be present")

		assert.Empty(t, ids.PackageIDs)
		assert.Empty(t, ids.PackageURLs)

		assert.Len(t, ids.VendorProductPairs, 1)
		assert.Equal(t, component.Pair{Vendor: "vim", Product: "vim"}, ids.VendorProductPairs[0])

		assert.Len(t, ids.WFNs, 2)
		wfn1 := createWFN("vim", "vim")
		assert.True(t, ids.WFNs.Contains(wfn1), "contains the right WFN")
		wfn2 := createWFN("debian", "vim")
		assert.True(t, ids.WFNs.Contains(wfn2), "contains the right WFN")
	})

	t.Run("VPNormalization", func(t *testing.T) {
		t.Parallel()

		ids := idsForCVEs["CVE-2026-0004"]
		require.NotNil(t, ids, "CVE-2026-0004 should be present")

		assert.Len(t, ids.VendorProductPairs, 2)
		assert.Contains(t, ids.VendorProductPairs, component.Pair{Vendor: "n/a", Product: "specialtool"})
		assert.Contains(t, ids.VendorProductPairs, component.Pair{Vendor: "upper", Product: "case"})
	})

	t.Run("CPENormalization_VersionStripped", func(t *testing.T) {
		t.Parallel()

		ids := idsForCVEs["CVE-2026-0001"]
		require.NotNil(t, ids)
		for _, wfn := range ids.WFNs {
			assert.Equal(t, cpe.AVAny, wfn.Version.Type, "version should be ANY")
			assert.Equal(t, cpe.AVAny, wfn.Update.Type)
			assert.Equal(t, cpe.AVAny, wfn.Edition.Type)
		}
	})

	t.Run("DeduplicationAcrossADPAndCNA", func(t *testing.T) {
		t.Parallel()

		ids := idsForCVEs["CVE-2026-0003"]
		require.NotNil(t, ids)
		assert.Len(t, ids.VendorProductPairs, 1)
	})
}

func TestGetIDsForCVEs_EdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		dir       string
		expectErr bool
		expectLen int
	}{
		{
			name:      "invalid JSON propagates error",
			dir:       "invalid_json",
			expectErr: true,
		},
		{
			name:      "empty directory returns empty map",
			dir:       "empty",
			expectErr: false,
			expectLen: 0,
		},
		{
			name:      "non-CVE files are ignored",
			dir:       "ignored_files",
			expectErr: false,
			expectLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			idsForCVEs, err := newService(tt.dir).GetIDsForCVEs(t.Context())
			if tt.expectErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Len(t, idsForCVEs, tt.expectLen)
		})
	}
}

func TestGetIDsForCVEs_InvalidCPESkipped(t *testing.T) {
	t.Parallel()

	idsForCVEs, err := newService("invalid_cpe").GetIDsForCVEs(t.Context())
	require.NoError(t, err)

	ids := idsForCVEs["CVE-2026-0005"]
	require.NotNil(t, ids)

	assert.Len(t, ids.VendorProductPairs, 1)
	assert.Equal(t, component.Pair{Vendor: "nginx", Product: "nginx"}, ids.VendorProductPairs[0])

	assert.Len(t, ids.WFNs, 1)
	wfn := createWFN("nginx", "nginx")
	assert.True(t, ids.WFNs.Contains(wfn), "contains the right WFN")
}

func TestGetIDsForCVEs_ContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := newService("valid").GetIDsForCVEs(ctx)
	assert.ErrorIs(t, err, context.Canceled)
}

// drainChannels consumes both channels from ReceiveCVEs and returns results and errors.
func drainChannels(
	resCh <-chan *cve_v5.CVEV5,
	errCh <-chan error,
) ([]*cve_v5.CVEV5, []error) {
	var cves []*cve_v5.CVEV5
	var errs []error

	for resCh != nil || errCh != nil {
		select {
		case cve, ok := <-resCh:
			if !ok {
				resCh = nil
				continue
			}
			if cve != nil {
				cves = append(cves, cve)
			}
		case err, ok := <-errCh:
			if !ok {
				errCh = nil
				continue
			}
			if err != nil {
				errs = append(errs, err)
			}
		}
	}
	return cves, errs
}

func TestReceiveCVEs_ChannelsCloseAfterCompletion(t *testing.T) {
	t.Parallel()

	cves, errs := drainChannels(newService("valid").ReceiveCVEs(t.Context()))

	assert.Empty(t, errs)
	assert.Len(t, cves, 4, "should receive all 4 CVE files from testdata/valid")
}

func TestReceiveCVEs_ErrorOnMalformedJSON(t *testing.T) {
	t.Parallel()

	_, errs := drainChannels(newService("invalid_json").ReceiveCVEs(t.Context()))

	assert.NotEmpty(t, errs)
}
