package cpe

import (
	"errors"
	"fmt"
)

// AVType distinguishes the three logical states of a WFN attribute value.
type AVType int

const (
	AVAny AVType = iota // *
	AVNA                // -
	AVString
)

type AttributeValue struct {
	Type  AVType
	Value string // only meaningful when Type is AVString
}

func Any() AttributeValue              { return AttributeValue{Type: AVAny} }
func NA() AttributeValue               { return AttributeValue{Type: AVNA} }
func StringAV(s string) AttributeValue { return AttributeValue{Type: AVString, Value: s} }

func (av AttributeValue) IsAny() bool    { return av.Type == AVAny }
func (av AttributeValue) IsNA() bool     { return av.Type == AVNA }
func (av AttributeValue) IsString() bool { return av.Type == AVString }

// Equal reports attribute-wise equality. String comparisons are case-insensitive.
func (av AttributeValue) Equal(other AttributeValue) bool {
	if av.Type != other.Type {
		return false
	}
	if av.Type == AVString {
		return asciiEqualFold(av.Value, other.Value)
	}

	return true
}

// String returns the logical representation of the value:
// "*" for ANY, "-" for NA, and the raw value string otherwise.
func (av AttributeValue) String() string {
	switch av.Type {
	case AVAny:
		return "*"
	case AVNA:
		return "-"
	case AVString:
		return av.Value
	}

	return av.Value // should be unreachable, if all cases are checked
}

// Part constants for the WFN Part attribute.
const (
	PartApplication = "a"
	PartOS          = "o"
	PartHardware    = "h"
)

// WFN is a Well-Formed Name — the canonical logical representation of a CPE.
type WFN struct {
	Part      AttributeValue
	Vendor    AttributeValue
	Product   AttributeValue
	Version   AttributeValue
	Update    AttributeValue
	Edition   AttributeValue
	Language  AttributeValue
	SWEdition AttributeValue
	TargetSW  AttributeValue
	TargetHW  AttributeValue
	Other     AttributeValue
}

// NewWFN returns a WFN with all attributes set to ANY.
func NewWFN() WFN { return WFN{} }

// String returns the WFN as CPE 2.3 formatted string.
func (w *WFN) String() string {
	return w.FormatAsCPE23String()
}

// Equal reports whether two WFNs are attribute-wise equal.
func (w *WFN) Equal(other WFN) bool {
	return w.Part.Equal(other.Part) &&
		w.Vendor.Equal(other.Vendor) &&
		w.Product.Equal(other.Product) &&
		w.Version.Equal(other.Version) &&
		w.Update.Equal(other.Update) &&
		w.Edition.Equal(other.Edition) &&
		w.Language.Equal(other.Language) &&
		w.SWEdition.Equal(other.SWEdition) &&
		w.TargetSW.Equal(other.TargetSW) &&
		w.TargetHW.Equal(other.TargetHW) &&
		w.Other.Equal(other.Other)
}

// Validate checks that all attribute values in the WFN are well-formed.
func (w *WFN) Validate() error {
	if err := validatePartAV(w.Part); err != nil {
		return fmt.Errorf("part: %w", err)
	}

	for _, a := range [...]struct {
		name string
		av   AttributeValue
	}{
		{"vendor", w.Vendor},
		{"product", w.Product},
		{"version", w.Version},
		{"update", w.Update},
		{"edition", w.Edition},
		{"language", w.Language},
		{"sw_edition", w.SWEdition},
		{"target_sw", w.TargetSW},
		{"target_hw", w.TargetHW},
		{"other", w.Other},
	} {
		if a.av.Type == AVString { // skip ANY or NA
			if err := validateStringAV(a.av); err != nil {
				return fmt.Errorf("%s: %w", a.name, err)
			}
		}
	}

	return nil
}

// KeepOnlyVendorAndProduct sets all parts that are not the vendor or product to ANY.
func (w *WFN) KeepOnlyVendorAndProduct() {
	w.Version = Any()
	w.Update = Any()
	w.Edition = Any()
	w.Language = Any()
	w.SWEdition = Any()
	w.TargetSW = Any()
	w.TargetHW = Any()
	w.Other = Any()
}

// validatePartAV checks that the Part attribute holds a valid part letter.
func validatePartAV(av AttributeValue) error {
	if av.Type != AVString {
		return nil
	}

	switch av.Value {
	case PartApplication, PartOS, PartHardware:
		return nil
	}

	return fmt.Errorf("invalid part value %q, must be one of: 'a', 'o', or 'h'", av.Value)
}

// validateStringAV validates a generic bound-string attribute value.
func validateStringAV(av AttributeValue) error {
	if av.Type != AVString {
		return errors.New("attribute value is not a AVString")
	}

	if av.Value == "" {
		return errors.New("attribute string values cannot be empty")
	}

	return validateWildcardsAndEscapeSequences(av.Value)
}

// validateWildcardsAndEscapeSequences checks that wildcard and backslash positions in a stored attribute value string
// are valid per NIST IR 7695 §5.3.2.
//   - A trailing backslash is illegal.
//   - An unescaped * may only appear at the very start or very end of the value.
func validateWildcardsAndEscapeSequences(s string) error {
	n := len(s)
	for i := 0; i < n; i++ {
		switch s[i] {
		case '\\':
			if i+1 >= n {
				return errors.New("trailing backslash in value")
			}
			i++ // consume the escaped character
		case '*':
			if i != 0 && i != n-1 {
				return fmt.Errorf("embedded unescaped * at position %d is invalid", i)
			}
		default:
		}
	}
	return nil
}

// asciiEqualFold compares two ASCII strings case-insensitively without allocating.
func asciiEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		ca, cb := a[i], b[i]
		if ca == cb {
			continue
		}
		// Fold ASCII letters.
		if ca >= 'A' && ca <= 'Z' {
			ca |= 0x20
		}
		if cb >= 'A' && cb <= 'Z' {
			cb |= 0x20
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// StripEscapes removes backslash escaping from a WFN value string so that
// literal characters can be compared (e.g. \* -> *).
func StripEscapes(s string) string {
	// Fast path: no backslash present.
	hasBackslash := false
	for i := range s {
		if s[i] == '\\' {
			hasBackslash = true
			break
		}
	}
	if !hasBackslash {
		return s
	}

	out := make([]rune, 0, len(s))
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		if runes[i] == '\\' && i+1 < len(runes) {
			out = append(out, runes[i+1])
			i++
			continue
		}
		out = append(out, runes[i])
	}

	return string(out)
}
