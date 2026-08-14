package assessment //nolint:testpackage // white-box tests require access to unexported types

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStrategy_ForMap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		strategy strategy
		want     bool
	}{
		{strategyKey, false},
		{strategyOverwrite, false},
		{strategyPreserve, false},
		{strategyMapReplace, true},
		{strategyMapPreserve, true},
	}

	for _, tt := range tests {
		t.Run(tt.strategy.String(), func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.strategy.isForMap())
		})
	}
}

func TestParseTag(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  strategy
		ok    bool
	}{
		{"key", strategyKey, true},
		{"overwrite", strategyOverwrite, true},
		{"preserve", strategyPreserve, true},
		{"map,replace", strategyMapReplace, true},
		{"map,preserve", strategyMapPreserve, true},
		{"invalid", 0, false},
		{"", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()

			got, ok := parseTag(tt.input)
			assert.Equal(t, tt.ok, ok)
			if ok {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestExtractMergeFields(t *testing.T) {
	t.Parallel()

	type testItem struct {
		ID       string  `json:"id"        merge:"key"`
		Name     string  `json:"name"      merge:"overwrite"`
		Score    float64 `json:"score"     merge:"overwrite"`
		UserNote string  `json:"user_note" merge:"preserve"`
	}

	want := []mergeField{
		{Name: "ID", JSONName: "id", Strategy: strategyKey, Index: 0},
		{Name: "Name", JSONName: "name", Strategy: strategyOverwrite, Index: 1},
		{Name: "Score", JSONName: "score", Strategy: strategyOverwrite, Index: 2},
		{Name: "UserNote", JSONName: "user_note", Strategy: strategyPreserve, Index: 3},
	}

	got := extractMergeFields(reflect.TypeFor[testItem]())

	assert.Equal(t, want, got)
}
