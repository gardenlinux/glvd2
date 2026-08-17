package assessment

import (
	"fmt"
	"reflect"
)

// mergeRecords applies incoming overwrite fields onto existing while preserving preserve fields.
// If existing is empty (new assessment record), all fields from incoming are used as-is.
// This is a pure function with no I/O.
func mergeRecords(cache *mergeSpec, existing, incoming Record) (Record, error) {
	if existing.ID != "" && existing.ID != incoming.ID {
		return Record{}, fmt.Errorf(
			"merge ID mismatch: existing %q vs incoming %q",
			existing.ID, incoming.ID,
		)
	}

	// New assessment record: take everything from incoming.
	if existing.ID == "" {
		return incoming, nil
	}

	merged, ok := mergeStructs(cache, existing, incoming).(Record)
	if !ok {
		panic("merge: unexpected result type from mergeStructs")
	}

	return merged, nil
}

// mergeStructs merges two struct values using the cache's record field metadata.
// Overwrite fields are taken from incoming, preserve fields are kept from existing.
// Key fields are taken from incoming (to handle the case where existing is zero-value).
// Map fields are merged per-key using their value struct's tags.
//
// Both existing and incoming must match the cache's root type.
// Panics if either does not.
func mergeStructs(cache *mergeSpec, existing, incoming any) any {
	existingVal := reflect.ValueOf(existing)
	incomingVal := reflect.ValueOf(incoming)

	if existingVal.Type() != cache.rootType {
		panic(fmt.Sprintf(
			"mergeStructs: existing type %s does not match cache root type %s",
			existingVal.Type(), cache.rootType,
		))
	}
	if incomingVal.Type() != cache.rootType {
		panic(fmt.Sprintf(
			"mergeStructs: incoming type %s does not match cache root type %s",
			incomingVal.Type(), cache.rootType,
		))
	}

	merged := reflect.New(existingVal.Type()).Elem()

	for _, fm := range cache.recordFields {
		switch {
		case fm.Strategy == strategyKey:
			// Key comes from incoming so that new records (zero existing) get the ID.
			merged.Field(fm.Index).Set(incomingVal.Field(fm.Index))
		case fm.Strategy == strategyOverwrite:
			merged.Field(fm.Index).Set(incomingVal.Field(fm.Index))
		case fm.Strategy == strategyPreserve:
			merged.Field(fm.Index).Set(existingVal.Field(fm.Index))
		case fm.Strategy.isForMap():
			mergedMap := mergeMap(
				cache, fm.Strategy, existingVal.Field(fm.Index), incomingVal.Field(fm.Index),
			)
			merged.Field(fm.Index).Set(mergedMap)
		}
	}

	return merged.Interface()
}

// mergeMap merges two map[string]Struct values using the merge tags from Struct.
// The strategy parameter controls whether existing keys not in incoming are preserved or removed:
//   - map,preserve: keys only in existing are kept (used to keep e.g. EOL releases)
//   - map,replace:  keys only in existing are dropped
//
// For keys present in both, the value struct is always merged field-by-field:
// overwrite fields come from incoming, preserve fields come from existing.
// This means even with map,replace, manual overrides within a key are preserved.
func mergeMap(cache *mergeSpec, s strategy, existing, incoming reflect.Value) reflect.Value {
	if existing.Type() != incoming.Type() {
		panic(fmt.Sprintf(
			"mergeMap: existing type %s does not match incoming type %s",
			existing.Type(), incoming.Type(),
		))
	}

	if incoming.IsNil() && existing.IsNil() {
		return reflect.Zero(existing.Type())
	}

	valueType := existing.Type().Elem()

	fields := cache.valueFieldsFor(valueType)

	merged := reflect.MakeMap(existing.Type())

	// For map,preserve: copy all existing entries first (EOL keys stay).
	if s == strategyMapPreserve && !existing.IsNil() {
		for _, key := range existing.MapKeys() {
			merged.SetMapIndex(key, existing.MapIndex(key))
		}
	}

	if !incoming.IsNil() {
		for _, key := range incoming.MapKeys() {
			incomingVal := incoming.MapIndex(key)

			var existingVal reflect.Value
			if !existing.IsNil() {
				existingVal = existing.MapIndex(key)
			}

			mergedVal := reflect.New(valueType).Elem()

			for _, fm := range fields {
				switch fm.Strategy { //nolint:exhaustive // only overwrite/preserve are valid in map values
				case strategyOverwrite:
					mergedVal.Field(fm.Index).Set(incomingVal.Field(fm.Index))
				case strategyPreserve:
					if existingVal.IsValid() {
						mergedVal.Field(fm.Index).Set(existingVal.Field(fm.Index))
					}
				default:
					panic(
						"mergeMap: unsupported merge strategy used inside a map! only overwrite and preserve are supported.",
					)
				}
			}

			merged.SetMapIndex(key, mergedVal)
		}
	}

	if merged.Len() == 0 {
		return reflect.Zero(existing.Type())
	}

	return merged
}
