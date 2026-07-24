package cpe

import (
	"fmt"
	"strings"
)

// ParseCPE22 parses a "CPE 2.2"-formatted string into a WFN.
func ParseCPE22(s string) (WFN, error) {
	const errorPrefix = "cpe v2.2 parsing"

	const expectedPrefix = "cpe:/"
	if !strings.HasPrefix(s, expectedPrefix) {
		return WFN{}, fmt.Errorf("%s: invalid prefix, expected %q", errorPrefix, expectedPrefix)
	}
	body := s[len(expectedPrefix):]

	// Split into at most 7 colon-separated fields:
	//   [0] part, [1] vendor, [2] product, [3] version, [4] update, [5] edition, [6] language
	fields := strings.Split(body, ":")
	const minAmountOfFields = 3
	const maxAmountOfFields = 7
	if len(fields) < minAmountOfFields {
		return WFN{}, fmt.Errorf("%s: too few components: %d (min %d)", errorPrefix, len(fields), minAmountOfFields)
	} else if len(fields) > maxAmountOfFields {
		return WFN{}, fmt.Errorf("%s: too many components: %d (max %d)", errorPrefix, len(fields), maxAmountOfFields)
	}

	wildcardReplacer := strings.NewReplacer(
		"\x01", "?",
		"\x02", "*")

	w := NewWFN()
	for i, dst := range []*AttributeValue{
		&w.Part, &w.Vendor, &w.Product, &w.Version, &w.Update, &w.Edition,
		&w.Language,
	} {
		if i >= len(fields) {
			break // update, edition, and language can be left out
		}

		// first percent-decode
		f, err := percentDecode(fields[i])
		if err != nil {
			return WFN{}, fmt.Errorf("%s: %w", errorPrefix, err)
		}

		// replace raw ASCII control characters with logical CPE wildcards
		f = wildcardReplacer.Replace(f)

		*dst = decodeAV22(f)
	}

	// optionally the Edition field can contain fields introduced by CPE 2.3 (separated by ~)
	decodePackedEdition22(&w)

	err := w.Validate()
	if err != nil {
		return WFN{}, fmt.Errorf("%s: %w", errorPrefix, err)
	}

	return w, nil
}

// decodeAV22 decodes a single CPE 2.2 field into an AttributeValue.
// An empty string maps to ANY.
func decodeAV22(raw string) AttributeValue {
	switch raw {
	case "", "*":
		return Any()
	case "-":
		return NA()
	default:
		return StringAV(raw)
	}
}

// decodePackedEdition22 further decodes the edition field, if it contains additional fields introduced by CPE 2.3.
func decodePackedEdition22(w *WFN) {
	if !w.Edition.IsString() || !strings.HasPrefix(w.Edition.Value, "~") {
		return
	}

	dsts := []*AttributeValue{&w.Edition, &w.SWEdition, &w.TargetSW, &w.TargetHW, &w.Other}
	raw := w.Edition.Value
	subFields := strings.SplitN(raw[1:], "~", len(dsts))
	for i, f := range subFields {
		*dsts[i] = decodeAV22(f)
	}
}

func unhexChar(c byte) int {
	const offsetForA = 10
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + offsetForA
	case c >= 'A' && c <= 'F':
		return int(c-'A') + offsetForA
	}

	return -1
}

// percentDecode percent-decodes the given string like 'a%20b' to 'a b'. It returns an error for any invalid or
// incomplete %XX sequence.
func percentDecode(s string) (string, error) {
	if !strings.ContainsRune(s, '%') { // fast path: nothing to decode
		return s, nil
	}

	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); {
		b := s[i]
		if b != '%' { // consume until encoded part appears
			err := sb.WriteByte(b)
			if err != nil {
				return "", err
			}

			i++
			continue
		}

		// positioned now at an encoded sequence like %20, where the number is in hex

		if i+2 >= len(s) { // at least two more characters are required to have a valid encoding
			return "", fmt.Errorf("incomplete percent-encoding at position %d", i)
		}

		hi := unhexChar(s[i+1])
		lo := unhexChar(s[i+2])
		if hi < 0 || lo < 0 {
			return "", fmt.Errorf("invalid percent-encoding %%%s at position %d", s[i+1:i+3], i)
		}
		err := sb.WriteByte(byte(hi<<4 | lo)) //nolint:gosec // desired cut-off
		if err != nil {
			return "", err
		}

		i += 3
	}

	return sb.String(), nil
}
