package assessment //nolint:testpackage // white-box tests require access to unexported types

// Shared test structs for internal tests (merge and diff).

type testItem struct {
	ID       string  `json:"id"        merge:"key"`
	Name     string  `json:"name"      merge:"overwrite"`
	Score    float64 `json:"score"     merge:"overwrite"`
	UserNote string  `json:"user_note" merge:"preserve"`
}

type testMapValue struct {
	Status  string `json:"status"  merge:"overwrite"`
	Comment string `json:"comment" merge:"preserve"`
}

type testWithMap struct {
	ID    string                  `json:"id"    merge:"key"`
	Title string                  `json:"title" merge:"overwrite"`
	Items map[string]testMapValue `json:"items" merge:"map,preserve"`
}

type testWithMapReplace struct {
	ID    string                  `json:"id"    merge:"key"`
	Title string                  `json:"title" merge:"overwrite"`
	Items map[string]testMapValue `json:"items" merge:"map,replace"`
}

type testNested struct {
	ID   string    `json:"id"   merge:"key"`
	Data testInner `json:"data" merge:"overwrite"`
	Keep testInner `json:"keep" merge:"preserve"`
}

type testInner struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}
