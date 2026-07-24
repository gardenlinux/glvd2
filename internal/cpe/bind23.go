package cpe

import (
	"strings"
)

// FormatAsCPE23String returns the CPE 2.3 formatted string binding of the WFN.
func (w *WFN) FormatAsCPE23String() string {
	var sb strings.Builder
	// "cpe:2.3:" + 11 fields joined by ":"
	const cpeStrBufferSize = 128
	sb.Grow(cpeStrBufferSize)
	sb.WriteString("cpe:2.3:")
	avs := [11]AttributeValue{
		w.Part, w.Vendor, w.Product, w.Version, w.Update,
		w.Edition, w.Language, w.SWEdition, w.TargetSW, w.TargetHW, w.Other,
	}
	for i, av := range avs {
		if i > 0 {
			sb.WriteByte(':')
		}
		writeAV23(&sb, av)
	}
	return sb.String()
}

// writeAV23 writes the CPE 2.3 representation of av into sb.
func writeAV23(sb *strings.Builder, av AttributeValue) {
	switch av.Type {
	case AVAny:
		sb.WriteByte('*')
	case AVNA:
		sb.WriteByte('-')
	case AVString:
		writeAVStringEscaped23(sb, av.Value)
	}
}

// writeAVStringEscaped23 writes s into sb with backslash escaping applied for all
// characters that require it in the CPE 2.3 binding).
func writeAVStringEscaped23(sb *strings.Builder, s string) {
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		ch := runes[i]
		// only pass already-escaped sequences through, if they must be escaped
		if ch == '\\' && i+1 < len(runes) {
			if mustEscape23(runes[i+1]) {
				sb.WriteRune(ch)
				sb.WriteRune(runes[i+1])
			} else {
				sb.WriteRune(runes[i+1])
			}
			i++
			continue
		}
		// Wildcards represent themselves.
		if ch == '*' || ch == '?' {
			sb.WriteRune(ch)
			continue
		}
		if mustEscape23(ch) {
			sb.WriteByte('\\')
		}
		sb.WriteRune(ch)
	}
}

// mustEscape23 reports whether ch must be backslash-escaped in the CPE 2.3 binding.
func mustEscape23(ch rune) bool {
	switch ch {
	case '!', '"', '#', '$', '%', '&', '\'', '(', ')', '+', ',', '/',
		':', ';', '<', '=', '>', '@', '[', '\\', ']', '^', '{', '|', '}', '~':
		return true
	default:
		return false
	}
}
