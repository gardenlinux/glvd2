package cpe

import (
	"errors"
	"fmt"
	"strings"
)

// ParseCPE23 parses a "CPE 2.3"-formatted string into a WFN.
func ParseCPE23(s string) (WFN, error) {
	const expectedPrefix = "cpe:2.3:"
	if !strings.HasPrefix(s, expectedPrefix) {
		return WFN{}, fmt.Errorf("cpe v2.3: invalid prefix, expected %q", expectedPrefix)
	}
	body := s[len(expectedPrefix):]

	// Split on unescaped ':' only; a backslash before ':' is an escaped colon
	// inside an attribute value, not a field separator.
	fields, err := splitOnUnescapedColons(body)
	if err != nil {
		return WFN{}, fmt.Errorf("cpe v2.3: %w", err)
	}
	const expectedNumberOfFields = 11
	if len(fields) != expectedNumberOfFields {
		return WFN{}, fmt.Errorf("cpe v2.3: expected 11 attribute fields, got %d", len(fields))
	}

	w := NewWFN()
	for i, dst := range []*AttributeValue{
		&w.Part, &w.Vendor, &w.Product, &w.Version, &w.Update, &w.Edition,
		&w.Language, &w.SWEdition, &w.TargetSW, &w.TargetHW, &w.Other,
	} {
		*dst = decodeAV23(fields[i])
	}

	err = w.Validate()
	if err != nil {
		return WFN{}, fmt.Errorf("cpe v2.3 parsing: %w", err)
	}

	return w, nil
}

// decodeAV23 decodes a single CPE 2.3 string attribute field into an AttributeValue.
func decodeAV23(raw string) AttributeValue {
	switch raw {
	case "*":
		return Any()
	case "-":
		return NA()
	default:
		return StringAV(strings.ToLower(raw))
	}
}

// splitOnUnescapedColons splits s on ':' characters that are not preceded by a backslash.
func splitOnUnescapedColons(s string) ([]string, error) {
	const maxNumberOfElementsWithHeadroom = 16
	fields := make([]string, 0, maxNumberOfElementsWithHeadroom) // expecting 11, but leave some headroom
	var cur strings.Builder
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		ch := runes[i]
		switch ch {
		case '\\':
			if i+1 >= len(runes) {
				return nil, errors.New("trailing backslash in input")
			}
			cur.WriteRune(ch)
			i++
			cur.WriteRune(runes[i])
		case ':':
			fields = append(fields, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(ch)
		}
	}
	fields = append(fields, cur.String())

	return fields, nil
}
