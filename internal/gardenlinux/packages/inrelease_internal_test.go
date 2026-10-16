package packages

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSelectInstalledVersions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   []Package
		want []Package
	}{
		{
			name: "backport displaces base version within an architecture",
			in: []Package{
				{Name: "perl", Source: "perl", Version: "5.40.1-3", SourceVersion: "5.40.1-3", Architecture: "amd64"},
				{
					Name:          "perl",
					Source:        "perl",
					Version:       "5.42.2-3gl0~bp1877",
					SourceVersion: "5.42.2-3gl0~bp1877",
					Architecture:  "amd64",
				},
			},
			want: []Package{
				{
					Name:          "perl",
					Source:        "perl",
					Version:       "5.42.2-3gl0~bp1877",
					SourceVersion: "5.42.2-3gl0~bp1877",
					Architecture:  "amd64",
				},
			},
		},
		{
			name: "backport drops base-version binaries even under different binary names",
			in: []Package{
				{Name: "perl", Source: "perl", Version: "5.40.1-3", SourceVersion: "5.40.1-3", Architecture: "amd64"},
				{
					Name:          "perl-base",
					Source:        "perl",
					Version:       "5.40.1-3",
					SourceVersion: "5.40.1-3",
					Architecture:  "amd64",
				},
				{
					Name:          "perl",
					Source:        "perl",
					Version:       "5.42.2-3gl0~bp1877",
					SourceVersion: "5.42.2-3gl0~bp1877",
					Architecture:  "amd64",
				},
			},
			want: []Package{
				{
					Name:          "perl",
					Source:        "perl",
					Version:       "5.42.2-3gl0~bp1877",
					SourceVersion: "5.42.2-3gl0~bp1877",
					Architecture:  "amd64",
				},
			},
		},
		{
			name: "architectures of the installed source version collapse to one entry",
			in: []Package{
				{Name: "libc6", Source: "glibc", Version: "2.31-13", SourceVersion: "2.31-13", Architecture: "amd64"},
				{
					Name:          "libc6",
					Source:        "glibc",
					Version:       "2.31-13+b1",
					SourceVersion: "2.31-13",
					Architecture:  "arm64",
				},
			},
			want: []Package{
				{
					Name:          "libc6",
					Source:        "glibc",
					Version:       "2.31-13+b1",
					SourceVersion: "2.31-13",
					Architecture:  "arm64",
				},
			},
		},
		{
			name: "unorderable candidate never displaces the chosen version",
			in: []Package{
				{Name: "foo", Source: "foo", Version: "1.0-1", SourceVersion: "1.0-1", Architecture: "amd64"},
				{
					Name:          "foo",
					Source:        "foo",
					Version:       "not a version",
					SourceVersion: "not a version",
					Architecture:  "amd64",
				},
			},
			want: []Package{
				{Name: "foo", Source: "foo", Version: "1.0-1", SourceVersion: "1.0-1", Architecture: "amd64"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, selectInstalledVersions(tt.in))
		})
	}
}
