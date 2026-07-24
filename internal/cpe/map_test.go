package cpe_test

import (
	"slices"
	"testing"

	"github.com/gardenlinux/glvd2/internal/cpe"
)

func makeWFN(vendor, product, version string) cpe.WFN {
	w := cpe.NewWFN()
	w.Part = cpe.StringAV("a")
	w.Vendor = cpe.StringAV(vendor)
	w.Product = cpe.StringAV(product)
	w.Version = cpe.StringAV(version)
	return w
}

func sortedKeys(wfns []cpe.WFN) []string {
	keys := make([]string, len(wfns))
	for i, w := range wfns {
		keys[i] = w.FormatAsCPE23String()
	}
	slices.Sort(keys)

	return keys
}

func TestMapAddUnique(t *testing.T) {
	t.Parallel()

	m := make(cpe.UniqueWFNMap)

	w1 := makeWFN("apache", "httpd", "2.4.51")
	w2 := makeWFN("nginx", "nginx", "1.24.0")

	if !m.Add(w1) {
		t.Error("first Add(w1) should return true")
	}
	if !m.Add(w2) {
		t.Error("first Add(w2) should return true")
	}
	if len(m) != 2 {
		t.Fatalf("len() = %d; want 2", len(m))
	}
}

func TestMapAddDuplicate(t *testing.T) {
	t.Parallel()

	m := make(cpe.UniqueWFNMap)
	w := makeWFN("apache", "httpd", "2.4.51")

	if !m.Add(w) {
		t.Error("first Add should return true")
	}
	if m.Add(w) {
		t.Error("second Add of identical WFN should return false")
	}
	if len(m) != 1 {
		t.Fatalf("len() = %d; want 1 after duplicate Add", len(m))
	}
}

func TestMapAddCaseInsensitive(t *testing.T) {
	t.Parallel()

	m := make(cpe.UniqueWFNMap)

	lower := makeWFN("apache", "httpd", "2.4.51")
	upper := makeWFN("Apache", "HTTPD", "2.4.51")

	m.Add(lower)
	if m.Add(upper) {
		t.Error("case-variant of already-present WFN should not be added")
	}
	if len(m) != 1 {
		t.Fatalf("len() = %d; want 1 for case-insensitive duplicate", len(m))
	}
}

func TestMapContains(t *testing.T) {
	t.Parallel()

	m := make(cpe.UniqueWFNMap)

	w := makeWFN("apache", "httpd", "2.4.51")
	absent := makeWFN("nginx", "nginx", "1.24.0")

	m.Add(w)

	if !m.Contains(w) {
		t.Error("Contains should return true for inserted WFN")
	}
	if m.Contains(absent) {
		t.Error("Contains should return false for WFN not in map")
	}
}

func TestMapRemovePresent(t *testing.T) {
	t.Parallel()

	m := make(cpe.UniqueWFNMap)

	w := makeWFN("apache", "httpd", "2.4.51")
	m.Add(w)

	if !m.Remove(w) {
		t.Error("Remove of present WFN should return true")
	}

	if len(m) != 0 {
		t.Fatalf("len() = %d; want 0 after remove", len(m))
	}
	if m.Contains(w) {
		t.Error("Contains should return false after removal")
	}
}

func TestMapRemoveAbsent(t *testing.T) {
	t.Parallel()

	m := make(cpe.UniqueWFNMap)

	w := makeWFN("apache", "httpd", "2.4.51")
	if m.Remove(w) {
		t.Error("Remove of absent WFN should return false")
	}

	if len(m) != 0 {
		t.Fatalf("len() = %d; want 0 unchanged after failed remove", len(m))
	}
}

func TestMapValues(t *testing.T) {
	t.Parallel()

	m := make(cpe.UniqueWFNMap)

	w1 := makeWFN("apache", "httpd", "2.4.51")
	w2 := makeWFN("nginx", "nginx", "1.24.0")
	w3 := makeWFN("microsoft", "iis", "10.0")
	m.Add(w1)
	m.Add(w2)
	m.Add(w3)

	vals := m.Values()
	if len(vals) != 3 {
		t.Fatalf("Values() returned %d elements; want 3", len(vals))
	}

	want := sortedKeys([]cpe.WFN{w1, w2, w3})
	got := sortedKeys(vals)
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Values()[%d] = %q; want %q", i, got[i], want[i])
		}
	}
}

func TestMapEach(t *testing.T) {
	t.Parallel()

	m := make(cpe.UniqueWFNMap)

	w1 := makeWFN("apache", "httpd", "2.4.51")
	w2 := makeWFN("nginx", "nginx", "1.24.0")
	w3 := makeWFN("microsoft", "iis", "10.0")
	m.Add(w1)
	m.Add(w2)
	m.Add(w3)

	t.Run("visits all elements", func(t *testing.T) {
		t.Parallel()

		seen := make(map[string]bool)
		m.Each(func(w cpe.WFN) bool {
			seen[w.FormatAsCPE23String()] = true
			return true
		})
		if len(seen) != 3 {
			t.Errorf("Each visited %d elements; want 3", len(seen))
		}
	})

	t.Run("early exit on false", func(t *testing.T) {
		t.Parallel()

		count := 0
		m.Each(func(_ cpe.WFN) bool {
			count++
			return false // stop after the first element
		})
		if count != 1 {
			t.Errorf("Each called function %d times after early-exit false; want 1", count)
		}
	})
}

func TestMapUnion(t *testing.T) {
	t.Parallel()

	w1 := makeWFN("apache", "httpd", "2.4.51")
	w2 := makeWFN("nginx", "nginx", "1.24.0")
	w3 := makeWFN("microsoft", "iis", "10.0")

	a := cpe.NewUniqueWFNMapFrom([]cpe.WFN{w1, w2})
	b := cpe.NewUniqueWFNMapFrom([]cpe.WFN{w2, w3}) // w2 is in both

	u := a.Union(b)

	if len(u) != 3 {
		t.Fatalf("Union Len() = %d; want 3", len(u))
	}
	for _, w := range []cpe.WFN{w1, w2, w3} {
		if !u.Contains(w) {
			t.Errorf("Union should contain %s", w.FormatAsCPE23String())
		}
	}
	// Originals must be unmodified.
	if len(a) != 2 {
		t.Errorf("Union modified a; Len() = %d, want 2", len(a))
	}
	if len(b) != 2 {
		t.Errorf("Union modified b; Len() = %d, want 2", len(b))
	}
}

func TestMapUnionEmpty(t *testing.T) {
	t.Parallel()

	w := makeWFN("apache", "httpd", "2.4.51")
	a := cpe.NewUniqueWFNMapFrom([]cpe.WFN{w})
	empty := make(cpe.UniqueWFNMap)

	if u := a.Union(empty); len(u) != 1 || !u.Contains(w) {
		t.Error("Union with empty map should equal original map")
	}
	if u := empty.Union(a); len(u) != 1 || !u.Contains(w) {
		t.Error("empty.Union(a) should equal a")
	}
}

func TestMapIntersection(t *testing.T) {
	t.Parallel()

	w1 := makeWFN("apache", "httpd", "2.4.51")
	w2 := makeWFN("nginx", "nginx", "1.24.0")
	w3 := makeWFN("microsoft", "iis", "10.0")

	a := cpe.NewUniqueWFNMapFrom([]cpe.WFN{w1, w2})
	b := cpe.NewUniqueWFNMapFrom([]cpe.WFN{w2, w3})

	i := a.Intersection(b)

	if len(i) != 1 {
		t.Fatalf("Intersection Len() = %d; want 1", len(i))
	}
	if !i.Contains(w2) {
		t.Errorf("Intersection should contain w2 (%s)", w2.FormatAsCPE23String())
	}
	if i.Contains(w1) || i.Contains(w3) {
		t.Error("Intersection should not contain w1 or w3")
	}
	// Originals must be unmodified.
	if len(a) != 2 {
		t.Errorf("Intersection modified a; Len() = %d, want 2", len(a))
	}
	if len(b) != 2 {
		t.Errorf("Intersection modified b; Len() = %d, want 2", len(b))
	}
}

func TestMapIntersectionDisjoint(t *testing.T) {
	t.Parallel()

	w1 := makeWFN("apache", "httpd", "2.4.51")
	w2 := makeWFN("nginx", "nginx", "1.24.0")

	a := cpe.NewUniqueWFNMapFrom([]cpe.WFN{w1})
	b := cpe.NewUniqueWFNMapFrom([]cpe.WFN{w2})

	if i := a.Intersection(b); len(i) != 0 {
		t.Errorf("Intersection of disjoint len(m) = %d; want 0", len(i))
	}
}

func TestMapDifference(t *testing.T) {
	t.Parallel()

	w1 := makeWFN("apache", "httpd", "2.4.51")
	w2 := makeWFN("nginx", "nginx", "1.24.0")
	w3 := makeWFN("microsoft", "iis", "10.0")

	a := cpe.NewUniqueWFNMapFrom([]cpe.WFN{w1, w2, w3})
	b := cpe.NewUniqueWFNMapFrom([]cpe.WFN{w2})

	d := a.Difference(b)

	if len(d) != 2 {
		t.Fatalf("Difference Len() = %d; want 2", len(d))
	}
	if !d.Contains(w1) || !d.Contains(w3) {
		t.Error("Difference should contain w1 and w3")
	}
	if d.Contains(w2) {
		t.Errorf("Difference should not contain w2 (%s)", w2.FormatAsCPE23String())
	}
	// Originals must be unmodified.
	if len(a) != 3 {
		t.Errorf("Difference modified a; Len() = %d, want 3", len(a))
	}
	if len(b) != 1 {
		t.Errorf("Difference modified b; Len() = %d, want 1", len(b))
	}
}

func TestMapDifferenceEmpty(t *testing.T) {
	t.Parallel()

	w := makeWFN("apache", "httpd", "2.4.51")
	a := cpe.NewUniqueWFNMapFrom([]cpe.WFN{w})
	empty := make(cpe.UniqueWFNMap)

	// a minus empty == a
	if d := a.Difference(empty); len(d) != 1 || !d.Contains(w) {
		t.Error("Difference from empty map should equal original map")
	}
	// empty minus a == empty
	if d := empty.Difference(a); len(d) != 0 {
		t.Errorf("empty.Difference(a) Len() = %d; want 0", len(d))
	}
}

func TestMapEachEmpty(t *testing.T) {
	t.Parallel()

	m := make(cpe.UniqueWFNMap)

	called := 0
	m.Each(func(_ cpe.WFN) bool {
		called++
		return true
	})
	if called != 0 {
		t.Errorf("Each on empty map called fn %d times; want 0", called)
	}
}

func TestMapUnionIndependentFromSources(t *testing.T) {
	t.Parallel()

	w1 := makeWFN("a", "p", "1")
	w2 := makeWFN("b", "q", "2")

	x := cpe.NewUniqueWFNMapFrom([]cpe.WFN{w1})
	y := cpe.NewUniqueWFNMapFrom([]cpe.WFN{w2})
	u := x.Union(y)

	u.Remove(w1)
	if !x.Contains(w1) {
		t.Error("removing from Union result must not affect source map x")
	}
}

func TestMapNewMapFromAllDuplicates(t *testing.T) {
	t.Parallel()

	w := makeWFN("a", "p", "1")
	m := cpe.NewUniqueWFNMapFrom([]cpe.WFN{w, w, w})
	if len(m) != 1 {
		t.Errorf("NewMapFrom all-duplicates Len = %d; want 1", len(m))
	}
}

func TestMapValuesFreshSlice(t *testing.T) {
	t.Parallel()

	w := makeWFN("a", "p", "1")
	s := cpe.NewUniqueWFNMapFrom([]cpe.WFN{w})

	v1 := s.Values()
	v2 := s.Values()
	if len(v1) != 1 || len(v2) != 1 {
		t.Fatalf("Values() should return 1 element; got %d and %d", len(v1), len(v2))
	}
	v1[0] = makeWFN("x", "y", "z")
	if !s.Contains(w) {
		t.Error("modifying Values() slice must not affect the map")
	}
	if v2[0].FormatAsCPE23String() != w.FormatAsCPE23String() {
		t.Error("modifying one Values() slice must not affect another")
	}
}

func TestMapIntersectionSmallLargeSwap(t *testing.T) {
	t.Parallel()

	large := make(cpe.UniqueWFNMap)
	for i := range 20 {
		large.Add(makeWFN("vendor", "product", string(rune('a'+i))))
	}

	shared := makeWFN("vendor", "product", "a")
	small := cpe.NewUniqueWFNMapFrom([]cpe.WFN{shared})

	i := large.Intersection(small)
	if len(i) != 1 {
		t.Errorf("Intersection Len = %d; want 1", len(i))
	}
	if !i.Contains(shared) {
		t.Error("Intersection should contain the shared element")
	}
}
