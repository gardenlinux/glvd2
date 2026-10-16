package assessment //nolint:testpackage // white-box tests require access to unexported types

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

// merge is a type-safe generic wrapper around [mergeStructs],
// used to test the merge mechanism with synthetic structs.
//
//nolint:ireturn // generic T return is intentional
func merge[T any](existing, incoming T) T {
	cache := newMergeSpec[T]()
	result := mergeStructs(cache, existing, incoming)

	typed, ok := result.(T)
	if !ok {
		panic(fmt.Sprintf("merge: unexpected result type %T", result))
	}

	return typed
}

func TestMerge_OverwriteAndPreserve(t *testing.T) {
	t.Parallel()

	existing := testItem{
		ID:       "item-1",
		Name:     "Old Name",
		Score:    5.0,
		UserNote: "human wrote this",
	}
	incoming := testItem{
		ID:       "item-1",
		Name:     "New Name",
		Score:    9.5,
		UserNote: "", // program doesn't provide this
	}

	merged := merge(existing, incoming)

	// Key: from incoming.
	assert.Equal(t, "item-1", merged.ID)
	// Overwrite: from incoming.
	assert.Equal(t, "New Name", merged.Name)
	assert.InDelta(t, 9.5, merged.Score, 0.001)
	// Preserve: from existing.
	assert.Equal(t, "human wrote this", merged.UserNote)
}

func TestMerge_NestedStruct(t *testing.T) {
	t.Parallel()

	existing := testNested{
		ID:   "n-1",
		Data: testInner{Value: "old", Count: 1},
		Keep: testInner{Value: "preserved", Count: 99},
	}
	incoming := testNested{
		ID:   "n-1",
		Data: testInner{Value: "new", Count: 42},
		Keep: testInner{Value: "ignored", Count: 0},
	}

	merged := merge(existing, incoming)

	// Overwrite struct: entire struct from incoming.
	assert.Equal(t, "new", merged.Data.Value)
	assert.Equal(t, 42, merged.Data.Count)
	// Preserve struct: entire struct from existing.
	assert.Equal(t, "preserved", merged.Keep.Value)
	assert.Equal(t, 99, merged.Keep.Count)
}

func TestMerge_MapPreserve_KeepsMissingKeys(t *testing.T) {
	t.Parallel()

	existing := testWithMap{
		ID:    "m-1",
		Title: "old",
		Items: map[string]testMapValue{
			"a": {Status: "active", Comment: "user note A"},
			"b": {Status: "old-b", Comment: "user note B"},
		},
	}
	incoming := testWithMap{
		ID:    "m-1",
		Title: "new",
		Items: map[string]testMapValue{
			"a": {Status: "updated"},
			// "b" not in incoming - should be preserved (map,preserve)
		},
	}

	merged := merge(existing, incoming)

	assert.Equal(t, "new", merged.Title)
	// "a": overwrite fields updated, preserve fields kept.
	assert.Equal(t, "updated", merged.Items["a"].Status)
	assert.Equal(t, "user note A", merged.Items["a"].Comment)
	// "b": preserved entirely (not in incoming).
	assert.Equal(t, "old-b", merged.Items["b"].Status)
	assert.Equal(t, "user note B", merged.Items["b"].Comment)
}

func TestMerge_MapReplace_RemovesMissingKeys(t *testing.T) {
	t.Parallel()

	existing := testWithMapReplace{
		ID:    "m-2",
		Title: "old",
		Items: map[string]testMapValue{
			"a": {Status: "active", Comment: "note A"},
			"b": {Status: "old-b", Comment: "note B"},
		},
	}
	incoming := testWithMapReplace{
		ID:    "m-2",
		Title: "new",
		Items: map[string]testMapValue{
			"a": {Status: "updated"},
			// "b" not in incoming - should be REMOVED (map,replace)
		},
	}

	merged := merge(existing, incoming)

	// "a": merged.
	assert.Equal(t, "updated", merged.Items["a"].Status)
	assert.Equal(t, "note A", merged.Items["a"].Comment)
	// "b": gone.
	_, exists := merged.Items["b"]
	assert.False(t, exists)
}

func TestMergeMap_PanicsOnTypeMismatch(t *testing.T) {
	t.Parallel()

	cache := newMergeSpec[testWithMap]()

	existing := reflect.ValueOf(map[string]testMapValue{
		"a": {Status: "active"},
	})

	type otherValue struct {
		Status string `json:"status" merge:"overwrite"`
	}
	incoming := reflect.ValueOf(map[string]otherValue{
		"a": {Status: "updated"},
	})

	assert.Panics(t, func() {
		mergeMap(cache, strategyMapPreserve, existing, incoming)
	})
}

func TestMerge_KeyFromIncoming(t *testing.T) {
	t.Parallel()

	existing := testItem{} // new record scenario
	incoming := testItem{
		ID:    "new-item",
		Name:  "New",
		Score: 1.0,
	}

	merged := merge(existing, incoming)

	assert.Equal(t, "new-item", merged.ID)
	assert.Equal(t, "New", merged.Name)
}

// TestMerge_Releases_PreservesManualAndEOL mirrors a release-status run: a relevant
// CVE rewrites the auto per-pkg breakdown for a maintained release while the human
// per-pkg override and an EOL release absent from the incoming record survive.
func TestMerge_Releases_PreservesManualAndEOL(t *testing.T) {
	t.Parallel()

	const (
		maintained = "2150.8.0"
		eol        = "934.0"
		purl       = "pkg:deb/debian/foo"
	)

	existing := Record{
		ID: "CVE-2024-1234",
		Releases: map[string]ReleaseDecision{
			maintained: {
				Auto: AutoReleaseStatus{Packages: map[string]PackageStatus{
					purl: {Reason: ReleaseReasonVersionVulnerable, ShippedVersion: "1.0-1"},
				}},
				Manual: ManualReleaseStatus{Packages: map[string]PackageOverride{
					purl: {Status: ReleaseStatusNotAffected, Justification: "backported"},
				}},
			},
			eol: {
				Auto: AutoReleaseStatus{Packages: map[string]PackageStatus{
					purl: {Reason: ReleaseReasonVersionFixed, ShippedVersion: "0.9-1"},
				}},
			},
		},
	}
	incoming := Record{
		ID: "CVE-2024-1234",
		Releases: map[string]ReleaseDecision{
			maintained: {
				Auto: AutoReleaseStatus{Packages: map[string]PackageStatus{
					purl: {Reason: ReleaseReasonVersionFixed, ShippedVersion: "2.0-1"},
				}},
			},
		},
	}

	merged := merge(existing, incoming)

	// The auto breakdown is overwritten by the incoming run.
	assert.Equal(t, "2.0-1", merged.Releases[maintained].Auto.Packages[purl].ShippedVersion)
	assert.Equal(t, ReleaseReasonVersionFixed, merged.Releases[maintained].Auto.Packages[purl].Reason)
	// The human per-pkg override is preserved and still drives the composite.
	assert.Equal(t, ReleaseStatusNotAffected, merged.Releases[maintained].Manual.Packages[purl].Status)
	assert.Equal(t, ReleaseStatusNotAffected, merged.Releases[maintained].CompositeStatus())
	// The EOL release, absent from the incoming record, survives untouched.
	assert.Equal(t, "0.9-1", merged.Releases[eol].Auto.Packages[purl].ShippedVersion)
}
