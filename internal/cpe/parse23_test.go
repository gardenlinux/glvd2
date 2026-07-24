package cpe_test

import (
	"testing"

	"github.com/gardenlinux/glvd2/internal/cpe"
)

func TestParseCPE23(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		input   string
		want    cpe.WFN
		wantErr bool
	}{
		{
			name:  "all ANY",
			input: "cpe:2.3:*:*:*:*:*:*:*:*:*:*:*",
			want:  cpe.NewWFN(),
		},
		{
			name:  "NA version",
			input: "cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*",
			want: func() cpe.WFN {
				w := cpe.NewWFN()
				w.Part = cpe.StringAV("a")
				w.Vendor = cpe.StringAV("vendor")
				w.Product = cpe.StringAV("product")
				w.Version = cpe.NA()
				return w
			}(),
		},
		{
			name:  "escaped colon in vendor",
			input: `cpe:2.3:a:colo\:n-enterprise:*:*:*:*:*:*:*:*:*`,
			want: func() cpe.WFN {
				w := cpe.NewWFN()
				w.Part = cpe.StringAV("a")
				w.Vendor = cpe.StringAV("colo\\:n-enterprise")
				w.Product = cpe.Any()
				return w
			}(),
		},
		{
			name:  "escaped dot",
			input: `cpe:2.3:a:microsoft:internet_explorer:8\.0:*:*:*:*:*:*:*`,
			want: func() cpe.WFN {
				w := cpe.NewWFN()
				w.Part = cpe.StringAV("a")
				w.Vendor = cpe.StringAV("microsoft")
				w.Product = cpe.StringAV("internet_explorer")
				w.Version = cpe.StringAV(`8\.0`)
				return w
			}(),
		},
		{
			name:  "trailing wildcard in version",
			input: "cpe:2.3:a:vendor:product:1.*:*:*:*:*:*:*:*",
			want: func() cpe.WFN {
				w := cpe.NewWFN()
				w.Part = cpe.StringAV("a")
				w.Vendor = cpe.StringAV("vendor")
				w.Product = cpe.StringAV("product")
				w.Version = cpe.StringAV("1.*")
				return w
			}(),
		},
		{
			name:  "os part",
			input: "cpe:2.3:o:canonical:ubuntu_linux:*:*:*:*:*:*:*:*",
			want: func() cpe.WFN {
				w := cpe.NewWFN()
				w.Part = cpe.StringAV("o")
				w.Vendor = cpe.StringAV("canonical")
				w.Product = cpe.StringAV("ubuntu_linux")
				return w
			}(),
		},
		{
			name:  "hardware part",
			input: "cpe:2.3:h:arm:cortex_a53:*:*:*:*:*:*:*:*",
			want: func() cpe.WFN {
				w := cpe.NewWFN()
				w.Part = cpe.StringAV("h")
				w.Vendor = cpe.StringAV("arm")
				w.Product = cpe.StringAV("cortex_a53")
				return w
			}(),
		},
		{
			name:  "part ANY",
			input: "cpe:2.3:*:vendor:product:1.0:*:*:*:*:*:*:*",
			want: func() cpe.WFN {
				w := cpe.NewWFN()
				w.Vendor = cpe.StringAV("vendor")
				w.Product = cpe.StringAV("product")
				w.Version = cpe.StringAV("1.0")
				return w
			}(),
		},
		{
			name:  "NA part",
			input: "cpe:2.3:-:vendor:product:*:*:*:*:*:*:*:*",
			want: func() cpe.WFN {
				w := cpe.NewWFN()
				w.Part = cpe.NA()
				w.Vendor = cpe.StringAV("vendor")
				w.Product = cpe.StringAV("product")
				return w
			}(),
		},
		{
			name:  "all extended fields set",
			input: "cpe:2.3:a:v:p:1.0:upd:ed:en:se:tsw:thw:oth",
			want: func() cpe.WFN {
				w := cpe.NewWFN()
				w.Part = cpe.StringAV("a")
				w.Vendor = cpe.StringAV("v")
				w.Product = cpe.StringAV("p")
				w.Version = cpe.StringAV("1.0")
				w.Update = cpe.StringAV("upd")
				w.Edition = cpe.StringAV("ed")
				w.Language = cpe.StringAV("en")
				w.SWEdition = cpe.StringAV("se")
				w.TargetSW = cpe.StringAV("tsw")
				w.TargetHW = cpe.StringAV("thw")
				w.Other = cpe.StringAV("oth")
				return w
			}(),
		},
		{
			name:    "invalid part string",
			input:   "cpe:2.3:x:vendor:product:*:*:*:*:*:*:*:*",
			wantErr: true,
		},
		{
			name:    "too few fields",
			input:   "cpe:2.3:a:vendor",
			wantErr: true,
		},
		{
			name:    "too many fields",
			input:   "cpe:2.3:a:v:p:1.0:*:*:*:*:*:*:*:extra",
			wantErr: true,
		},
		{
			name:    "embedded * invalid in bound string",
			input:   "cpe:2.3:a:v*end:p:*:*:*:*:*:*:*:*",
			wantErr: true,
		},
		{
			name:    "wrong field count",
			input:   "cpe:2.3:a:foo:bar",
			wantErr: true,
		},
		{
			name:    "invalid prefix",
			input:   "cpe:/a:foo:bar",
			wantErr: true,
		},
		{
			name:    "trailing backslash",
			input:   `cpe:2.3:a:vendor:product:1.0\:*:*:*:*:*:*:*`,
			wantErr: true, // trailing backslash inside the split result
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := cpe.ParseCPE23(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil (WFN=%v)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !got.Equal(tc.want) {
				t.Errorf("got  %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

// TestParseCPE23CaseNormalization verifies that the parser normalizes to lowercase.
func TestParseCPE23CaseNormalization(t *testing.T) {
	t.Parallel()

	w, err := cpe.ParseCPE23("cpe:2.3:A:VENDOR:PRODUCT:*:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if w.Vendor.IsString() && w.Vendor.Value != "vendor" {
		t.Errorf("vendor should be lowercase, got %q", w.Vendor.Value)
	}
	if w.Product.IsString() && w.Product.Value != "product" {
		t.Errorf("product should be lowercase, got %q", w.Vendor.Value)
	}
}
