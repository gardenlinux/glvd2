package assessment

import (
	"encoding"
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strconv"
)

// ChangeType describes what happened to a CVE assessment record.
type ChangeType int

const (
	Unchanged ChangeType = iota
	Created
	Updated
)

func (ct ChangeType) String() string {
	switch ct {
	case Unchanged:
		return "unchanged"
	case Created:
		return "created"
	case Updated:
		return "updated" //nolint:goconst // unrelated to test data values
	default:
		return "unknown"
	}
}

// FieldChange records a single field-level difference between old and new assessments.
type FieldChange struct {
	// Field is the ordered path segments to the changed value
	// e.g. ["screening", "auto_triage", "status"] or ["releases", "1877.8.0", "auto_triage", "status"].
	// Call Field.String() for the dot-joined display form.
	Field    FieldPath
	OldValue string // empty if field didn't exist before
	NewValue string
}

// ChangeSet holds all detected changes for a single CVE assessment record.
type ChangeSet struct {
	CVEID   string
	Type    ChangeType
	Changes []FieldChange
}

// HasChanges returns true if the change set represents an actual modification.
func (cs ChangeSet) HasChanges() bool {
	return cs.Type != Unchanged
}

// detectExternalOverwriteEdits returns the set of changes to program-owned (overwrite) fields
// between baseline and existing. A non-empty result means an external actor modified
// fields that only the program should write. Could happen with a faulty bot.
func detectExternalOverwriteEdits(cache *mergeSpec, baseline, existing Record) []FieldChange {
	baselineVal := reflect.ValueOf(baseline)
	existingVal := reflect.ValueOf(existing)

	var changes []FieldChange

	for _, fm := range cache.recordFields {
		switch {
		case fm.Strategy == strategyOverwrite:
			changes = append(changes, diffValue(
				FieldPath{fm.JSONName},
				baselineVal.Field(fm.Index),
				existingVal.Field(fm.Index),
			)...)

		case fm.Strategy.isForMap():
			baseMap := baselineVal.Field(fm.Index)
			existMap := existingVal.Field(fm.Index)
			changes = append(changes, detectExternalOverwriteEditsInMap(
				cache, FieldPath{fm.JSONName}, baseMap, existMap,
			)...)
		}
	}

	return changes
}

// detectExternalOverwriteEditsInMap compares two map[string]Struct values for overwrite-field differences.
func detectExternalOverwriteEditsInMap(
	cache *mergeSpec,
	fieldName FieldPath,
	baseline, existing reflect.Value,
) []FieldChange {
	sortedKeys := sortedMapKeys(baseline, existing)

	valueType := baseline.Type().Elem()
	fields := cache.valueFieldsFor(valueType)
	zeroVal := reflect.New(valueType).Elem()

	var changes []FieldChange

	for _, key := range sortedKeys {
		keyVal := reflect.ValueOf(key)

		baseEntry := baseline.MapIndex(keyVal)
		if !baseEntry.IsValid() {
			baseEntry = zeroVal
		}

		existEntry := existing.MapIndex(keyVal)
		if !existEntry.IsValid() {
			existEntry = zeroVal
		}

		for _, fm := range fields {
			if fm.Strategy != strategyOverwrite {
				continue
			}

			prefix := fieldName.Append(key).Append(fm.JSONName)
			changes = append(changes, diffValue(prefix, baseEntry.Field(fm.Index), existEntry.Field(fm.Index))...)
		}
	}

	return changes
}

// diffRecords compares the baseline and merged assessment records, producing a ChangeSet.
// All fields are compared (baseline is the state at the last program run).
// If baseline has an empty ID, the assessment record is treated as new (Created).
func diffRecords(cache *mergeSpec, baseline, merged Record) ChangeSet {
	cveID := merged.ID

	isNew := baseline.ID == ""
	if isNew {
		return ChangeSet{
			CVEID:   cveID,
			Type:    Created,
			Changes: diffStructs(cache, Record{ID: cveID}, merged),
		}
	}

	changes := diffStructs(cache, baseline, merged)
	if len(changes) == 0 {
		return ChangeSet{CVEID: cveID, Type: Unchanged}
	}

	return ChangeSet{
		CVEID:   cveID,
		Type:    Updated,
		Changes: changes,
	}
}

// diffStructs compares two struct values using the cache's record field metadata.
// All fields are compared (except key, which is identity). Returns field-level
// changes for all detected differences.
//
// Both old and updated must match the cache's root type.
// Panics if either does not (programming error).
func diffStructs(cache *mergeSpec, old, updated any) []FieldChange {
	oldVal := reflect.ValueOf(old)
	updatedVal := reflect.ValueOf(updated)

	if oldVal.Type() != cache.rootType {
		panic(fmt.Sprintf(
			"diffStructs: old type %s does not match cache root type %s",
			oldVal.Type(), cache.rootType,
		))
	}
	if updatedVal.Type() != cache.rootType {
		panic(fmt.Sprintf(
			"diffStructs: updated type %s does not match cache root type %s",
			updatedVal.Type(), cache.rootType,
		))
	}

	var changes []FieldChange

	for _, fm := range cache.recordFields {
		if fm.Strategy == strategyKey {
			continue
		}

		if fm.Strategy.isForMap() {
			changes = append(changes, diffMap(
				cache, FieldPath{fm.JSONName}, oldVal.Field(fm.Index), updatedVal.Field(fm.Index),
			)...)
			continue
		}

		oldField := oldVal.Field(fm.Index)
		updatedField := updatedVal.Field(fm.Index)

		changes = append(changes, diffValue(FieldPath{fm.JSONName}, oldField, updatedField)...)
	}

	return changes
}

// sortedMapKeys returns a sorted slice of all unique string keys across two reflect map values.
func sortedMapKeys(old, updated reflect.Value) []string {
	allKeys := make(map[string]struct{}, old.Len())

	if !old.IsNil() {
		for _, key := range old.MapKeys() {
			allKeys[key.String()] = struct{}{}
		}
	}

	if !updated.IsNil() {
		for _, key := range updated.MapKeys() {
			allKeys[key.String()] = struct{}{}
		}
	}

	return slices.Sorted(maps.Keys(allKeys))
}

// diffMap compares two map[string]Struct values, reporting field-level changes.
// All fields within the value struct are compared (except key fields).
// Keys are sorted for deterministic output.
func diffMap(cache *mergeSpec, fieldName FieldPath, old, updated reflect.Value) []FieldChange {
	sortedKeys := sortedMapKeys(old, updated)

	valueType := old.Type().Elem()

	fields := cache.valueFieldsFor(valueType)

	zeroVal := reflect.New(valueType).Elem()

	var changes []FieldChange

	for _, key := range sortedKeys {
		keyVal := reflect.ValueOf(key)

		oldEntry := old.MapIndex(keyVal)
		if !oldEntry.IsValid() {
			oldEntry = zeroVal
		}

		updatedEntry := updated.MapIndex(keyVal)
		if !updatedEntry.IsValid() {
			updatedEntry = zeroVal
		}

		for _, fm := range fields {
			if fm.Strategy == strategyKey {
				continue
			}

			prefix := fieldName.Append(key).Append(fm.JSONName)
			oldField := oldEntry.Field(fm.Index)
			updatedField := updatedEntry.Field(fm.Index)

			changes = append(changes, diffValue(prefix, oldField, updatedField)...)
		}
	}

	return changes
}

// diffStructField compares two struct values field by field, producing changes with path segments.
// Only exported fields are compared.
func diffStructField(prefix FieldPath, old, updated reflect.Value) []FieldChange {
	t := old.Type()
	changes := make([]FieldChange, 0, t.NumField())

	for i := range t.NumField() {
		sf := t.Field(i)
		if !sf.IsExported() {
			continue
		}

		fieldPath := prefix.Append(jsonFieldName(sf))

		oldField := old.Field(i)
		updatedField := updated.Field(i)

		changes = append(changes, diffValue(fieldPath, oldField, updatedField)...)
	}

	return changes
}

// diffValue compares two reflect.Values and returns field changes.
func diffValue(fieldPath FieldPath, old, updated reflect.Value) []FieldChange {
	switch old.Kind() { //nolint:exhaustive // only relevant kinds handled
	case reflect.String:
		oldStr := old.String()
		updatedStr := updated.String()
		if oldStr != updatedStr {
			return []FieldChange{{
				Field:    fieldPath,
				OldValue: oldStr,
				NewValue: updatedStr,
			}}
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		oldInt := old.Int()
		updatedInt := updated.Int()
		if oldInt != updatedInt {
			return []FieldChange{{
				Field:    fieldPath,
				OldValue: strconv.FormatInt(oldInt, 10),
				NewValue: strconv.FormatInt(updatedInt, 10),
			}}
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		oldUint := old.Uint()
		updatedUint := updated.Uint()
		if oldUint != updatedUint {
			return []FieldChange{{
				Field:    fieldPath,
				OldValue: strconv.FormatUint(oldUint, 10),
				NewValue: strconv.FormatUint(updatedUint, 10),
			}}
		}
	case reflect.Bool:
		oldBool := old.Bool()
		updatedBool := updated.Bool()
		if oldBool != updatedBool {
			return []FieldChange{{
				Field:    fieldPath,
				OldValue: strconv.FormatBool(oldBool),
				NewValue: strconv.FormatBool(updatedBool),
			}}
		}
	case reflect.Float32, reflect.Float64:
		oldFloat := old.Float()
		updatedFloat := updated.Float()
		if oldFloat != updatedFloat {
			bitSize := 64
			if old.Kind() == reflect.Float32 {
				bitSize = 32
			}
			return []FieldChange{{
				Field:    fieldPath,
				OldValue: strconv.FormatFloat(oldFloat, 'f', -1, bitSize),
				NewValue: strconv.FormatFloat(updatedFloat, 'f', -1, bitSize),
			}}
		}
	case reflect.Pointer:
		return diffPointer(fieldPath, old, updated)
	case reflect.Struct:
		if isLeafStruct(old.Type()) {
			oldStr := marshalJSON(old.Interface())
			updatedStr := marshalJSON(updated.Interface())
			if oldStr != updatedStr {
				return []FieldChange{{
					Field:    fieldPath,
					OldValue: oldStr,
					NewValue: updatedStr,
				}}
			}
			return nil
		}
		return diffStructField(fieldPath, old, updated)
	case reflect.Slice, reflect.Map:
		if !reflect.DeepEqual(old.Interface(), updated.Interface()) {
			return []FieldChange{{
				Field:    fieldPath,
				OldValue: marshalJSON(old.Interface()),
				NewValue: marshalJSON(updated.Interface()),
			}}
		}
	default:
		panic(fmt.Sprintf(
			"diffValue: unsupported kind %s at path %s",
			old.Kind(), fieldPath,
		))
	}

	return nil
}

// diffPointer compares two pointer values.
// If both nil: no change. If one nil: reports the change.
// If both non-nil: recurses into the pointed-to value.
func diffPointer(fieldPath FieldPath, old, updated reflect.Value) []FieldChange {
	oldNil := old.IsNil()
	updatedNil := updated.IsNil()

	switch {
	case oldNil && updatedNil:
		return nil
	case oldNil:
		return []FieldChange{{
			Field:    fieldPath,
			OldValue: "",
			NewValue: marshalJSON(updated.Elem().Interface()),
		}}
	case updatedNil:
		return []FieldChange{{
			Field:    fieldPath,
			OldValue: marshalJSON(old.Elem().Interface()),
			NewValue: "",
		}}
	default:
		return diffValue(fieldPath, old.Elem(), updated.Elem())
	}
}

//nolint:gochecknoglobals // cached immutable reflect.Type descriptors
var (
	textMarshalerType = reflect.TypeFor[encoding.TextMarshaler]()
	jsonMarshalerType = reflect.TypeFor[json.Marshaler]()
)

// isLeafStruct reports whether a struct type should be treated as an opaque
// leaf value during diffing (compared and serialized as a whole) rather than
// recursed into field by field.
// This applies to types that implement encoding.TextMarshaler or json.Marshaler
// (e.g. time.Time), whose meaningful state lives in unexported fields that
// diffStructField would otherwise skip.
func isLeafStruct(t reflect.Type) bool {
	ptr := reflect.PointerTo(t)
	return t.Implements(textMarshalerType) || ptr.Implements(textMarshalerType) ||
		t.Implements(jsonMarshalerType) || ptr.Implements(jsonMarshalerType)
}

// marshalJSON serializes a value to JSON for use in FieldChange values.
// Falls back to fmt.Sprintf if marshaling fails.
func marshalJSON(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(data)
}
