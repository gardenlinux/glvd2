package assessment

import (
	"fmt"
	"reflect"
	"strings"
)

// Tag string constants used for both parsing and display.
const (
	tagKey         = "key"
	tagOverwrite   = "overwrite"
	tagPreserve    = "preserve"
	tagMapReplace  = "map,replace"
	tagMapPreserve = "map,preserve"
)

// strategy describes how a field should be handled during merge and diff.
type strategy int

const (
	// strategyKey means the field is the assessment record's identity (never changes).
	strategyKey strategy = iota

	// strategyOverwrite means the program always writes this field from incoming.
	strategyOverwrite

	// strategyPreserve means the program never touches this field.
	strategyPreserve

	// strategyMapReplace means the field is a map[string]Struct where values are merged
	// per their struct's tags. Keys not in incoming are removed.
	strategyMapReplace

	// strategyMapPreserve means the field is a map[string]Struct where values are merged
	// per their struct's tags. Keys not in incoming are preserved (EOL semantics).
	strategyMapPreserve
)

// String returns the human-readable name of the strategy.
func (s strategy) String() string {
	switch s {
	case strategyKey:
		return tagKey
	case strategyOverwrite:
		return tagOverwrite
	case strategyPreserve:
		return tagPreserve
	case strategyMapReplace:
		return tagMapReplace
	case strategyMapPreserve:
		return tagMapPreserve
	default:
		return "unknown"
	}
}

// parseTag converts a merge struct tag value into a strategy.
func parseTag(tag string) (strategy, bool) {
	switch tag {
	case tagKey:
		return strategyKey, true
	case tagOverwrite:
		return strategyOverwrite, true
	case tagPreserve:
		return strategyPreserve, true
	case tagMapReplace:
		return strategyMapReplace, true
	case tagMapPreserve:
		return strategyMapPreserve, true
	default:
		return 0, false
	}
}

// isForMap returns true if this strategy is exclusive to maps.
func (s strategy) isForMap() bool {
	return s == strategyMapReplace || s == strategyMapPreserve
}

// mergeField holds parsed metadata for a single struct field.
type mergeField struct {
	Name     string
	JSONName string
	Strategy strategy
	Index    int
}

// extractMergeFields extracts field metadata from a struct type using the "merge" tag.
// Only fields with a valid merge tag are returned.
func extractMergeFields(t reflect.Type) []mergeField {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}

	var fields []mergeField
	for i := range t.NumField() {
		f := t.Field(i)
		tag := f.Tag.Get("merge")
		if tag == "" {
			continue
		}

		s, ok := parseTag(tag)
		if !ok {
			continue
		}

		fields = append(fields, mergeField{
			Name:     f.Name,
			JSONName: jsonFieldName(f),
			Strategy: s,
			Index:    i,
		})
	}

	return fields
}

// jsonFieldName extracts the JSON field name from a struct field's json tag.
func jsonFieldName(f reflect.StructField) string {
	tag := f.Tag.Get("json")
	if tag == "" || tag == "-" {
		return f.Name
	}

	name, _, _ := strings.Cut(tag, ",")

	return name
}

// mergeSpec holds all pre-computed field metadata for a root struct type and its map-value types.
// It is constructed once via [newMergeSpec] and passed through the service layer,
// eliminating the need for global caches or repeated reflection.
type mergeSpec struct {
	rootType     reflect.Type
	recordFields []mergeField
	valueFields  map[reflect.Type][]mergeField
}

// newMergeSpec constructs a validated mergeSpec by reflecting on T and its map-value types.
// It panics if any exported field of T is missing a merge tag or if map fields are misconfigured.
// This is intended to be called once at application startup.
func newMergeSpec[T any]() *mergeSpec {
	t := reflect.TypeFor[T]()
	for f := range t.Fields() {
		if f.IsExported() && f.Tag.Get("merge") == "" {
			panic(fmt.Sprintf("%s field %s missing merge tag", t.Name(), f.Name))
		}
	}

	recordFields := extractMergeFields(t)
	valueFields := make(map[reflect.Type][]mergeField)

	// Validate and extract map value type fields.
	for _, fm := range recordFields {
		if !fm.Strategy.isForMap() {
			continue
		}

		ft := t.Field(fm.Index).Type
		if ft.Kind() != reflect.Map {
			panic(fmt.Sprintf(
				"%s field %s tagged as map but is %s", t.Name(), fm.Name, ft.Kind(),
			))
		}

		valueType := ft.Elem()
		vf := extractMergeFields(valueType)
		if len(vf) == 0 {
			panic(fmt.Sprintf(
				"%s field %s is a map but value type %s has no merge tags",
				t.Name(), fm.Name, valueType.Name(),
			))
		}

		for sf := range valueType.Fields() {
			if sf.IsExported() && sf.Tag.Get("merge") == "" {
				panic(fmt.Sprintf(
					"map value type %s field %s missing merge tag",
					valueType.Name(), sf.Name,
				))
			}
		}

		valueFields[valueType] = vf
	}

	return &mergeSpec{
		rootType:     t,
		recordFields: recordFields,
		valueFields:  valueFields,
	}
}

// valueFieldsFor returns the pre-computed field metadata for a map-value type.
// Panics if the type was not registered during spec construction.
func (s *mergeSpec) valueFieldsFor(t reflect.Type) []mergeField {
	fields, ok := s.valueFields[t]
	if !ok {
		panic("mergeSpec: no fields registered for type " + t.Name())
	}

	return fields
}
