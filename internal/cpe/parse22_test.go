package cpe_test

import (
	"testing"

	"github.com/gardenlinux/glvd2/internal/cpe"
)

func TestParseCPE22(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		input   string
		want    cpe.WFN
		wantErr bool
	}{
		{
			name:  "minimal three components",
			input: "cpe:/a:apache:http_server",
			want: func() cpe.WFN {
				w := cpe.NewWFN()
				w.Part = cpe.StringAV("a")
				w.Vendor = cpe.StringAV("apache")
				w.Product = cpe.StringAV("http_server")
				return w
			}(),
		},
		{
			name:  "full 7 components",
			input: "cpe:/a:microsoft:internet_explorer:8.0:sp1:*:en-us",
			want: func() cpe.WFN {
				w := cpe.NewWFN()
				w.Part = cpe.StringAV("a")
				w.Vendor = cpe.StringAV("microsoft")
				w.Product = cpe.StringAV("internet_explorer")
				w.Version = cpe.StringAV("8.0")
				w.Update = cpe.StringAV("sp1")
				w.Edition = cpe.Any()
				w.Language = cpe.StringAV("en-us")
				return w
			}(),
		},
		{
			name:  "NA value",
			input: "cpe:/a:vendor:product:-",
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
			name:  "percent-encoded wildcard value (%01 for ?)",
			input: "cpe:/a:microsoft:internet_explorer:8.%01",
			want: func() cpe.WFN {
				w := cpe.NewWFN()
				w.Part = cpe.StringAV("a")
				w.Vendor = cpe.StringAV("microsoft")
				w.Product = cpe.StringAV("internet_explorer")
				w.Version = cpe.StringAV("8.?")
				return w
			}(),
		},
		{
			// not valid by the standard (should be %01), but can happen in the real world
			name:  "percent-encdoed wildcard value (%3f for ?)",
			input: "cpe:/a:microsoft:internet_explorer:8.%3f",
			want: func() cpe.WFN {
				w := cpe.NewWFN()
				w.Part = cpe.StringAV("a")
				w.Vendor = cpe.StringAV("microsoft")
				w.Product = cpe.StringAV("internet_explorer")
				w.Version = cpe.StringAV("8.?")
				return w
			}(),
		},
		{
			name:  "percent-encoded wildcard value (%02 for *)",
			input: "cpe:/a:microsoft:internet_explorer:8.%02",
			want: func() cpe.WFN {
				w := cpe.NewWFN()
				w.Part = cpe.StringAV("a")
				w.Vendor = cpe.StringAV("microsoft")
				w.Product = cpe.StringAV("internet_explorer")
				w.Version = cpe.StringAV("8.*")
				return w
			}(),
		},
		{
			// not valid by the standard (should be %02), but can happen in the real world
			name:  "percent-encoded wildcard value (%2a for *)",
			input: "cpe:/a:microsoft:internet_explorer:8.%2a",
			want: func() cpe.WFN {
				w := cpe.NewWFN()
				w.Part = cpe.StringAV("a")
				w.Vendor = cpe.StringAV("microsoft")
				w.Product = cpe.StringAV("internet_explorer")
				w.Version = cpe.StringAV("8.*")
				return w
			}(),
		},
		{
			name:  "percent-encoded colon in product name",
			input: "cpe:/a:vendor:product%3Asuffix",
			want: func() cpe.WFN {
				w := cpe.NewWFN()
				w.Part = cpe.StringAV("a")
				w.Vendor = cpe.StringAV("vendor")
				w.Product = cpe.StringAV("product:suffix")
				return w
			}(),
		},
		{
			name:    "invalid prefix",
			input:   "cpe:2.3:a:foo:bar:*:*:*:*:*:*:*:*",
			wantErr: true,
		},
		{
			name:    "too many components",
			input:   "cpe:/a:b:c:d:e:f:g:h",
			wantErr: true,
		},
		{
			name:    "bad percent encoding",
			input:   "cpe:/a:vendor:prod%ax",
			wantErr: true,
		},
		{
			name:    "empty body",
			input:   "cpe:/",
			wantErr: true,
		},
		{
			name:  "all-ANY body",
			input: "cpe:/*:*:*:*:*:*:*",
			want:  cpe.NewWFN(), // part="*" -> ANY, rest ANY
		},
		{
			name:  "NA edition component",
			input: "cpe:/a:v:p:1.0:update:-",
			want: func() cpe.WFN {
				w := cpe.NewWFN()
				w.Part = cpe.StringAV("a")
				w.Vendor = cpe.StringAV("v")
				w.Product = cpe.StringAV("p")
				w.Version = cpe.StringAV("1.0")
				w.Update = cpe.StringAV("update")
				w.Edition = cpe.NA()
				return w
			}(),
		},
		{
			name:  "packed edition",
			input: "cpe:/a:vendor:product:1.0:update:~ed~swed~tsw~thw~other",
			want: func() cpe.WFN {
				w := cpe.NewWFN()
				w.Part = cpe.StringAV("a")
				w.Vendor = cpe.StringAV("vendor")
				w.Product = cpe.StringAV("product")
				w.Version = cpe.StringAV("1.0")
				w.Update = cpe.StringAV("update")
				w.Edition = cpe.StringAV("ed")
				w.SWEdition = cpe.StringAV("swed")
				w.TargetSW = cpe.StringAV("tsw")
				w.TargetHW = cpe.StringAV("thw")
				w.Other = cpe.StringAV("other")
				return w
			}(),
		},
		{
			name:  "packed edition with fewer than 5 sub-fields",
			input: "cpe:/a:v:p:1.0:update:~ed~se",
			want: func() cpe.WFN {
				w := cpe.NewWFN()
				w.Part = cpe.StringAV("a")
				w.Vendor = cpe.StringAV("v")
				w.Product = cpe.StringAV("p")
				w.Version = cpe.StringAV("1.0")
				w.Update = cpe.StringAV("update")
				w.Edition = cpe.StringAV("ed")
				w.SWEdition = cpe.StringAV("se")
				return w
			}(),
		},
		{
			name:  "star version maps to ANY",
			input: "cpe:/a:v:p:*",
			want: func() cpe.WFN {
				w := cpe.NewWFN()
				w.Part = cpe.StringAV("a")
				w.Vendor = cpe.StringAV("v")
				w.Product = cpe.StringAV("p")
				w.Version = cpe.Any()
				return w
			}(),
		},
		{
			name:    "invalid part letter",
			input:   "cpe:/x:vendor:product",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := cpe.ParseCPE22(tc.input)
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
				t.Errorf("got %+v; want %+v", got, tc.want)
			}
		})
	}
}
