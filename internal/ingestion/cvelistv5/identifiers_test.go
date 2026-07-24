package cvelistv5 //nolint:testpackage // white-box test: needs access to unexported merge

import (
	"testing"

	"github.com/gardenlinux/glvd2/internal/component"
	"github.com/gardenlinux/glvd2/internal/cpe"
	"github.com/stretchr/testify/assert"
)

func TestMerge(t *testing.T) {
	t.Parallel()

	createWFN := func(vendor, product string) cpe.WFN {
		return cpe.WFN{Part: cpe.StringAV("a"), Vendor: cpe.StringAV(vendor), Product: cpe.StringAV(product)}
	}

	t.Run("uninitialized", func(t *testing.T) {
		t.Parallel()

		ids := &Identifiers{}
		ids.merge(Identifiers{
			VendorProductPairs: []component.Pair{{Vendor: "v", Product: "p"}},
			WFNs:               cpe.NewUniqueWFNMapFrom([]cpe.WFN{createWFN("v", "p")}),
			PackageIDs:         []PackageIdentifier{{CollectionURL: "u", PackageName: "n"}},
			PackageURLs:        []string{"pkg:deb/debian/foo"},
		})

		assert.Len(t, ids.VendorProductPairs, 1)
		assert.Len(t, ids.WFNs, 1)
		assert.Len(t, ids.PackageIDs, 1)
		assert.Len(t, ids.PackageURLs, 1)
	})

	t.Run("with uninitialized WFNs, preserves existing fields", func(t *testing.T) {
		t.Parallel()

		ids := &Identifiers{
			VendorProductPairs: []component.Pair{{Vendor: "existing", Product: "pair"}},
		}
		ids.merge(Identifiers{
			WFNs: cpe.NewUniqueWFNMapFrom([]cpe.WFN{createWFN("v", "p")}),
		})

		assert.Len(t, ids.WFNs, 1)
		assert.Equal(t, "existing", ids.VendorProductPairs[0].Vendor)
	})

	t.Run("existing WFNs produces union", func(t *testing.T) {
		t.Parallel()

		ids := &Identifiers{WFNs: cpe.NewUniqueWFNMapFrom([]cpe.WFN{createWFN("v1", "p1")})}
		ids.merge(Identifiers{WFNs: cpe.NewUniqueWFNMapFrom([]cpe.WFN{createWFN("v2", "p2")})})

		assert.Len(t, ids.WFNs, 2)
		assert.True(t, ids.WFNs.Contains(createWFN("v1", "p1")))
		assert.True(t, ids.WFNs.Contains(createWFN("v2", "p2")))
	})

	t.Run("overlapping WFNs deduplicated", func(t *testing.T) {
		t.Parallel()

		wfn1 := createWFN("v", "p")
		wfn2 := createWFN("v", "p")
		ids := &Identifiers{WFNs: cpe.NewUniqueWFNMapFrom([]cpe.WFN{wfn1})}
		ids.merge(Identifiers{WFNs: cpe.NewUniqueWFNMapFrom([]cpe.WFN{wfn2})})

		assert.Len(t, ids.WFNs, 1)
	})

	t.Run("overlapping VendorProductPairs deduplicated", func(t *testing.T) {
		t.Parallel()

		pair1 := component.Pair{Vendor: "v", Product: "p"}
		pair2 := component.Pair{Vendor: "v", Product: "p"}
		ids := &Identifiers{VendorProductPairs: []component.Pair{pair1}}
		ids.merge(Identifiers{VendorProductPairs: []component.Pair{pair2}})

		assert.Len(t, ids.VendorProductPairs, 1)
	})

	t.Run("overlapping PackageIDs deduplicated", func(t *testing.T) {
		t.Parallel()

		pID1 := PackageIdentifier{CollectionURL: "u", PackageName: "n"}
		pID2 := PackageIdentifier{CollectionURL: "u", PackageName: "n"}
		ids := &Identifiers{PackageIDs: []PackageIdentifier{pID1}}
		ids.merge(Identifiers{PackageIDs: []PackageIdentifier{pID2}})

		assert.Len(t, ids.PackageIDs, 1)
	})

	t.Run("overlapping PackageURLs deduplicated", func(t *testing.T) {
		t.Parallel()

		ids := &Identifiers{PackageURLs: []string{"pkg:deb/debian/foo"}}
		ids.merge(Identifiers{PackageURLs: []string{"pkg:deb/debian/foo"}})

		assert.Len(t, ids.PackageURLs, 1)
	})

	t.Run("usage with empty other param", func(t *testing.T) {
		t.Parallel()

		ids := &Identifiers{
			VendorProductPairs: []component.Pair{{Vendor: "v", Product: "p"}},
			WFNs:               cpe.NewUniqueWFNMapFrom([]cpe.WFN{createWFN("v", "p")}),
			PackageIDs:         []PackageIdentifier{{CollectionURL: "c", PackageName: "p"}},
			PackageURLs:        []string{"pkg:deb/debian/foo"},
		}

		ids.merge(Identifiers{})

		assert.Len(t, ids.VendorProductPairs, 1)
		assert.Len(t, ids.WFNs, 1)
		assert.Len(t, ids.PackageIDs, 1)
		assert.Len(t, ids.PackageURLs, 1)
	})

	t.Run("sequential merges accumulate", func(t *testing.T) {
		t.Parallel()

		ids := &Identifiers{WFNs: make(cpe.UniqueWFNMap)}

		ids.merge(Identifiers{
			VendorProductPairs: []component.Pair{{Vendor: "a", Product: "a"}},
			WFNs:               cpe.NewUniqueWFNMapFrom([]cpe.WFN{createWFN("a", "a")}),
			PackageIDs:         []PackageIdentifier{{CollectionURL: "u1", PackageName: "n1"}},
			PackageURLs:        []string{"pkg:deb/debian/a"},
		})
		ids.merge(Identifiers{
			VendorProductPairs: []component.Pair{{Vendor: "b", Product: "b"}},
			WFNs:               cpe.NewUniqueWFNMapFrom([]cpe.WFN{createWFN("b", "b")}),
			PackageIDs:         []PackageIdentifier{{CollectionURL: "u2", PackageName: "n2"}},
			PackageURLs:        []string{"pkg:deb/debian/b"},
		})

		assert.Len(t, ids.VendorProductPairs, 2)
		assert.Len(t, ids.WFNs, 2)
		assert.Len(t, ids.PackageIDs, 2)
		assert.Len(t, ids.PackageURLs, 2)
	})

	t.Run("no aliasing for the WFNMap (clones it)", func(t *testing.T) {
		t.Parallel()

		sourceWFNs := cpe.NewUniqueWFNMapFrom([]cpe.WFN{createWFN("v", "p")})

		ids := &Identifiers{} // uninitliazed WFN map (nil)
		ids.merge(Identifiers{WFNs: sourceWFNs})

		// Mutating the source should not affect the returned WFN map from merge.
		newWFN := createWFN("new", "new")
		sourceWFNs.Add(newWFN)

		assert.False(t, ids.WFNs.Contains(newWFN),
			"merge should clone the map, not alias it")
	})
}
