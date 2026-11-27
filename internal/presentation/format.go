package presentation

import (
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gardenlinux/glvd2/internal/assessment"
)

// dateFormat is the sortable, display-friendly date layout used across the site.
const dateFormat = "2006-01-02"

// formatDate renders t in [dateFormat], or the empty string for the zero time.
func formatDate(t time.Time) string {
	if t.IsZero() {
		return ""
	}

	return t.Format(dateFormat)
}

func relevanceText(status assessment.TriageStatus) string {
	if status == assessment.StatusUndecided {
		return "undecided"
	}

	return string(status)
}

// formatInteger renders an integer with comma thousands separators.
func formatInteger(n int) string {
	s := strconv.Itoa(n)
	sign := ""
	if strings.HasPrefix(s, "-") {
		sign, s = "-", s[1:]
	}

	var b strings.Builder
	for i, digit := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteRune(',')
		}
		b.WriteRune(digit)
	}

	return sign + b.String()
}

func displayLabel(value string) string {
	if value == "" {
		return "Unknown"
	}

	text := strings.ReplaceAll(strings.ToLower(value), "-", " ")
	r, size := utf8.DecodeRuneInString(text)

	return strings.ToUpper(string(r)) + text[size:]
}
