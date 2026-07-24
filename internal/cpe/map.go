package cpe

import (
	"maps"
	"strings"
)

type UniqueWFNMap map[string]WFN // key: lowercased CPE 2.3 representation

// wfnKey returns the map key for UniqueWFNMap.
func wfnKey(wfn WFN) string {
	return strings.ToLower(wfn.FormatAsCPE23String())
}

func NewUniqueWFNMapFrom(l []WFN) UniqueWFNMap {
	out := make(UniqueWFNMap, len(l))

	for _, v := range l {
		out.Add(v)
	}

	return out
}

// Add inserts wfn into the map. If an equal WFN is already present, the map is unchanged and returns false.
// Otherwise it inserts wfn and returns true.
func (m UniqueWFNMap) Add(wfn WFN) bool {
	k := wfnKey(wfn)

	if _, exists := m[k]; exists {
		return false
	}

	m[k] = wfn

	return true
}

// Remove deletes the WFN equal to wfn from the map.
// It returns true if an element was removed, or false if wfn was not present.
func (m UniqueWFNMap) Remove(wfn WFN) bool {
	k := wfnKey(wfn)

	_, exists := m[k]
	delete(m, k)

	return exists
}

// Contains reports whether the map holds a WFN equal to wfn.
func (m UniqueWFNMap) Contains(wfn WFN) bool {
	_, ok := m[wfnKey(wfn)]

	return ok
}

// Values returns a new slice containing all WFNs in the map in an unspecified order.
// The slice is a copy; mutations to it do not affect the map.
func (m UniqueWFNMap) Values() []WFN {
	out := make([]WFN, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}

	return out
}

// Each calls fn for every WFN in the map in an unspecified order.
// If fn returns false, iteration stops immediately.
func (m UniqueWFNMap) Each(fn func(WFN) bool) {
	for _, v := range m {
		if !fn(v) {
			return
		}
	}
}

// Union returns a new UniqueWFNMap containing all WFNs from both m and other.
// Neither m nor other is modified.
func (m UniqueWFNMap) Union(other UniqueWFNMap) UniqueWFNMap {
	out := maps.Clone(m)
	maps.Copy(out, other)

	return out
}

// Intersection returns a new UniqueWFNMap containing only WFNs that are present in both m and other.
// Neither m nor other is modified.
func (m UniqueWFNMap) Intersection(other UniqueWFNMap) UniqueWFNMap {
	// Iterate over the smaller map to minimise work.
	small, large := &m, &other
	if len(*small) > len(*large) {
		small, large = large, small
	}

	out := make(UniqueWFNMap, len(*small))
	for k := range *small {
		if v, ok := (*large)[k]; ok {
			out[k] = v
		}
	}

	return out
}

// Difference returns a new UniqueWFNMap containing the WFNs that are in m but not in other.
// Neither m nor other is modified.
func (m UniqueWFNMap) Difference(other UniqueWFNMap) UniqueWFNMap {
	out := make(UniqueWFNMap, len(m))

	for k, v := range m {
		if _, ok := other[k]; !ok {
			out[k] = v
		}
	}

	return out
}
