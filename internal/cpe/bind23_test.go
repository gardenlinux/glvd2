package cpe_test

import (
	"testing"

	"github.com/gardenlinux/glvd2/internal/cpe"
)

func TestFormatAsCPE23String(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		input cpe.WFN
		want  string
	}{
		{
			name:  "all ANY",
			input: cpe.NewWFN(),
			want:  "cpe:2.3:*:*:*:*:*:*:*:*:*:*:*",
		},
		{
			name: "NA version",
			input: func() cpe.WFN {
				w := cpe.NewWFN()
				w.Part = cpe.StringAV("a")
				w.Vendor = cpe.StringAV("vendor")
				w.Product = cpe.StringAV("product")
				w.Version = cpe.NA()
				return w
			}(),
			want: "cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*",
		},
		{
			name: "escaped colon in vendor",
			input: func() cpe.WFN {
				w := cpe.NewWFN()
				w.Part = cpe.StringAV("a")
				w.Vendor = cpe.StringAV(`colo:n-enterprise`)
				w.Product = cpe.Any()
				return w
			}(),
			want: `cpe:2.3:a:colo\:n-enterprise:*:*:*:*:*:*:*:*:*`,
		},
		{
			name: "escaped dot should not pass through",
			input: func() cpe.WFN {
				w := cpe.NewWFN()
				w.Part = cpe.StringAV("a")
				w.Vendor = cpe.StringAV("microsoft")
				w.Product = cpe.StringAV("internet_explorer")
				w.Version = cpe.StringAV(`8\.0`)
				return w
			}(),
			want: `cpe:2.3:a:microsoft:internet_explorer:8.0:*:*:*:*:*:*:*`,
		},
		{
			name: "trailing wildcard in version",
			input: func() cpe.WFN {
				w := cpe.NewWFN()
				w.Part = cpe.StringAV("a")
				w.Vendor = cpe.StringAV("vendor")
				w.Product = cpe.StringAV("product")
				w.Version = cpe.StringAV("1.*")
				return w
			}(),
			want: "cpe:2.3:a:vendor:product:1.*:*:*:*:*:*:*:*",
		},
		{
			name: "os part",
			input: func() cpe.WFN {
				w := cpe.NewWFN()
				w.Part = cpe.StringAV("o")
				w.Vendor = cpe.StringAV("canonical")
				w.Product = cpe.StringAV("ubuntu_linux")
				w.Version = cpe.StringAV("20.04")
				return w
			}(),
			want: "cpe:2.3:o:canonical:ubuntu_linux:20.04:*:*:*:*:*:*:*",
		},
		{
			name: "hardware part",
			input: func() cpe.WFN {
				w := cpe.NewWFN()
				w.Part = cpe.StringAV("h")
				w.Vendor = cpe.StringAV("arm")
				w.Product = cpe.StringAV("cortex_a53")
				return w
			}(),
			want: "cpe:2.3:h:arm:cortex_a53:*:*:*:*:*:*:*:*",
		},
		{
			name: "part ANY",
			input: func() cpe.WFN {
				w := cpe.NewWFN()
				w.Vendor = cpe.StringAV("vendor")
				w.Product = cpe.StringAV("product")
				w.Version = cpe.StringAV("1.0")
				return w
			}(),
			want: "cpe:2.3:*:vendor:product:1.0:*:*:*:*:*:*:*",
		},
		{
			name: "NA part",
			input: func() cpe.WFN {
				w := cpe.NewWFN()
				w.Part = cpe.NA()
				w.Vendor = cpe.StringAV("vendor")
				w.Product = cpe.StringAV("product")
				return w
			}(),
			want: "cpe:2.3:-:vendor:product:*:*:*:*:*:*:*:*",
		},
		{
			name: "all extended fields set",
			input: func() cpe.WFN {
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
			want: "cpe:2.3:a:v:p:1.0:upd:ed:en:se:tsw:thw:oth",
		},
		{
			name: "not escaped special characters",
			input: func() cpe.WFN {
				w := cpe.NewWFN()
				w.Part = cpe.StringAV("a")
				w.Vendor = cpe.StringAV("foo.bar")
				w.Product = cpe.StringAV("foo-bar")
				w.Version = cpe.StringAV("1.?")
				w.Update = cpe.StringAV("upd")
				w.Edition = cpe.StringAV("foo_bar")
				w.Language = cpe.StringAV("en")
				return w
			}(),
			want: `cpe:2.3:a:foo.bar:foo-bar:1.?:upd:foo_bar:en:*:*:*:*`,
		},
		{
			name: "escaped special characters",
			input: func() cpe.WFN {
				w := cpe.NewWFN()
				w.Part = cpe.StringAV("a")
				w.Vendor = cpe.StringAV("foo")
				w.Product = cpe.StringAV("bar")
				w.Version = cpe.StringAV("1.?")
				w.Update = cpe.StringAV("upd")
				w.Edition = cpe.StringAV("foo:bar")
				w.Language = cpe.StringAV("en")
				w.SWEdition = cpe.StringAV("foo/bar")
				w.TargetSW = cpe.StringAV("tsw")
				w.TargetHW = cpe.StringAV("thw")
				w.Other = cpe.StringAV("oth~")
				return w
			}(),
			want: `cpe:2.3:a:foo:bar:1.?:upd:foo\:bar:en:foo\/bar:tsw:thw:oth\~`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := tc.input.String()
			if got != tc.want {
				t.Errorf("(%v).String() = %v; want %v", tc.input, got, tc.want)
			}
		})
	}
}
