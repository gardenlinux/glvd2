package cpe_test

import (
	"strings"
	"testing"

	"github.com/gardenlinux/glvd2/internal/cpe"
)

func TestAttributeValueConstructors(t *testing.T) {
	t.Parallel()

	a := cpe.Any()
	if !a.IsAny() {
		t.Error("Any() should be ANY")
	}

	n := cpe.NA()
	if !n.IsNA() {
		t.Error("NA() should be NA")
	}

	s := cpe.StringAV("foo")
	if !s.IsString() || s.Value != "foo" {
		t.Error("StringAV should be AVString with value foo")
	}
}

func TestAttributeValueEqual(t *testing.T) {
	t.Parallel()

	cases := []struct {
		a, b cpe.AttributeValue
		want bool
	}{
		{cpe.Any(), cpe.Any(), true},
		{cpe.NA(), cpe.NA(), true},
		{cpe.Any(), cpe.NA(), false},
		{cpe.NA(), cpe.Any(), false},
		{cpe.StringAV("foo"), cpe.StringAV("foo"), true},
		{cpe.StringAV("FOO"), cpe.StringAV("foo"), true},
		{cpe.StringAV("foo"), cpe.StringAV("FOO"), true},
		{cpe.StringAV("foo"), cpe.StringAV("bar"), false},
		{cpe.Any(), cpe.StringAV("foo"), false},
		{cpe.NA(), cpe.StringAV("foo"), false},
	}
	for _, tc := range cases {
		got := tc.a.Equal(tc.b)
		if got != tc.want {
			t.Errorf("(%v).Equal(%v) = %v; want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestAttributeValueString(t *testing.T) {
	t.Parallel()

	cases := []struct {
		av   cpe.AttributeValue
		want string
	}{
		{cpe.Any(), "*"},
		{cpe.NA(), "-"},
		{cpe.StringAV("foo"), "foo"},
		{cpe.StringAV(""), ""},
	}
	for _, tc := range cases {
		got := tc.av.String()
		if got != tc.want {
			t.Errorf("(%v).String() = %q; want %q", tc.av, got, tc.want)
		}
	}
}

func TestAttributeValueTypeCheckHelpers(t *testing.T) {
	t.Parallel()

	a := cpe.Any()
	if !a.IsAny() {
		t.Error("IsAny() should be true for cpe.Any()")
	}
	if a.IsNA() || a.IsString() {
		t.Error("Any should only satisfy IsAny()")
	}

	n := cpe.NA()
	if !n.IsNA() {
		t.Error("IsNA() should be true for cpe.NA()")
	}
	if n.IsAny() || n.IsString() {
		t.Error("NA should only satisfy IsNA()")
	}

	s := cpe.StringAV("x")
	if !s.IsString() {
		t.Error("IsString() should be true for cpe.StringAV()")
	}
	if s.IsAny() || s.IsNA() {
		t.Error("StringAV should only satisfy IsString()")
	}
}

func TestWFNEqual(t *testing.T) {
	t.Parallel()

	w1 := cpe.NewWFN()
	w1.Vendor = cpe.StringAV("apache")
	w2 := cpe.NewWFN()
	w2.Vendor = cpe.StringAV("apache")
	if !w1.Equal(w2) {
		t.Error("identical WFNs should be equal")
	}

	w2.Product = cpe.StringAV("httpd")
	if w1.Equal(w2) {
		t.Error("different WFNs should not be equal")
	}
}

func TestWFNValidate(t *testing.T) {
	t.Parallel()

	w := cpe.NewWFN()
	w.Part = cpe.StringAV("a")
	if err := w.Validate(); err != nil {
		t.Errorf("valid WFN should not error: %v", err)
	}

	w.Part = cpe.StringAV("x")
	if err := w.Validate(); err == nil {
		t.Error("invalid part should return error")
	}

	w2 := cpe.NewWFN()
	w2.Vendor = cpe.StringAV("foo*bar") // embedded * is invalid
	if err := w2.Validate(); err == nil {
		t.Error("embedded * should return validation error")
	}
}

// WFN field-by-field Equal coverage.
func TestWFNEqualAllFields(t *testing.T) {
	t.Parallel()

	fields := []struct {
		name string
		a    cpe.WFN
	}{
		{"Version", cpe.WFN{Version: cpe.StringAV("1.0")}},
		{"Update", cpe.WFN{Update: cpe.StringAV("sp1")}},
		{"Edition", cpe.WFN{Edition: cpe.StringAV("ed")}},
		{"Language", cpe.WFN{Language: cpe.StringAV("en")}},
		{"SWEdition", cpe.WFN{SWEdition: cpe.StringAV("se")}},
		{"TargetSW", cpe.WFN{TargetSW: cpe.StringAV("ts")}},
		{"TargetHW", cpe.WFN{TargetHW: cpe.StringAV("th")}},
		{"Other", cpe.WFN{Other: cpe.StringAV("ot")}},
	}

	for _, tc := range fields {
		b := cpe.NewWFN()
		if tc.a.Equal(b) {
			t.Errorf("WFNs differing on %s should not be equal", tc.name)
		}
		if !tc.a.Equal(tc.a) { //nolint:gocritic // purpose of the test
			t.Errorf("WFN with %s set should equal itself", tc.name)
		}
	}
}

// WFN.Validate - every attribute that can be invalid.
func TestWFNValidateAllFields(t *testing.T) {
	t.Parallel()

	invalid := cpe.StringAV("a*b") // embedded * - invalid

	fields := []struct {
		name string
		cpe  cpe.WFN
	}{
		{"vendor", cpe.WFN{Vendor: invalid}},
		{"product", cpe.WFN{Product: invalid}},
		{"version", cpe.WFN{Version: invalid}},
		{"update", cpe.WFN{Update: invalid}},
		{"edition", cpe.WFN{Edition: invalid}},
		{"language", cpe.WFN{Language: invalid}},
		{"sw_edition", cpe.WFN{SWEdition: invalid}},
		{"target_sw", cpe.WFN{TargetSW: invalid}},
		{"target_hw", cpe.WFN{TargetHW: invalid}},
		{"other", cpe.WFN{Other: invalid}},
	}

	for _, tc := range fields {
		err := tc.cpe.Validate()
		if err == nil {
			t.Errorf("Validate with invalid %s should return error", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.name) {
			t.Errorf("Validate error for %s should mention the field name; got %q", tc.name, err.Error())
		}
	}
}

func TestWFNValidateEmptyString(t *testing.T) {
	t.Parallel()

	w := cpe.NewWFN()
	w.Vendor = cpe.StringAV("") // empty attribute value string is not allowed
	if err := w.Validate(); err == nil {
		t.Error("empty bound string should fail validation")
	}
}

func TestWFNValidateTrailingBackslash(t *testing.T) {
	t.Parallel()

	w := cpe.NewWFN()
	w.Vendor = cpe.StringAV(`foo\`) // trailing backslash
	if err := w.Validate(); err == nil {
		t.Error("trailing backslash in bound string should fail validation")
	}
}

func TestWFNValidatePartValues(t *testing.T) {
	t.Parallel()

	validParts := []string{"a", "o", "h"}
	for _, p := range validParts {
		w := cpe.NewWFN()
		w.Part = cpe.StringAV(p)
		if err := w.Validate(); err != nil {
			t.Errorf("part=%q should be valid, got: %v", p, err)
		}
	}
	for _, p := range []string{"x", "b", "application", ""} {
		w := cpe.NewWFN()
		w.Part = cpe.StringAV(p)
		err := w.Validate()
		if p == "" {
			if err == nil {
				t.Errorf("part=%q (empty string) should fail validation", p)
			}
			continue
		}
		if err == nil {
			t.Errorf("part=%q should be invalid", p)
		}
	}
}

// NewWFN zero values should be ANY.
func TestNewWFNAllAny(t *testing.T) {
	t.Parallel()

	w := cpe.NewWFN()
	avs := []cpe.AttributeValue{
		w.Part, w.Vendor, w.Product, w.Version, w.Update,
		w.Edition, w.Language, w.SWEdition, w.TargetSW, w.TargetHW, w.Other,
	}
	for i, av := range avs {
		if !av.IsAny() {
			t.Errorf("NewWFN field[%d] should be ANY, got %v", i, av)
		}
	}
}
