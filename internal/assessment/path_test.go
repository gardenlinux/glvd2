package assessment //nolint:testpackage // white-box tests require access to unexported types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		baseDir string
		cveID   string
		want    string
		wantErr bool
	}{
		{
			name:    "typical ID in mid-bucket",
			baseDir: "/base",
			cveID:   "CVE-2025-4176",
			want:    "/base/2025/4xxx/CVE-2025-4176.json",
		},
		{
			name:    "minimum valid sequence lands in bucket 0",
			baseDir: "/base",
			cveID:   "CVE-2024-1",
			want:    "/base/2024/0xxx/CVE-2024-1.json",
		},
		{
			name:    "sequence 999 is last entry of bucket 0",
			baseDir: "/base",
			cveID:   "CVE-2024-999",
			want:    "/base/2024/0xxx/CVE-2024-999.json",
		},
		{
			name:    "sequence 1000 is first entry of bucket 1",
			baseDir: "/base",
			cveID:   "CVE-2024-1000",
			want:    "/base/2024/1xxx/CVE-2024-1000.json",
		},
		{
			name:    "sequence 2000 is first entry of bucket 2",
			baseDir: "/base",
			cveID:   "CVE-2024-2000",
			want:    "/base/2024/2xxx/CVE-2024-2000.json",
		},
		{
			name:    "large sequence number",
			baseDir: "/base",
			cveID:   "CVE-2024-123456",
			want:    "/base/2024/123xxx/CVE-2024-123456.json",
		},
		{
			name:    "empty base dir produces relative path",
			baseDir: "",
			cveID:   "CVE-2021-44228",
			want:    "2021/44xxx/CVE-2021-44228.json",
		},
		{
			name:    "zero-padded sequence",
			baseDir: "/base",
			cveID:   "CVE-2024-0123",
			want:    "/base/2024/0xxx/CVE-2024-0123.json",
		},
		{
			name:    "invalid ID - wrong prefix",
			baseDir: "/base",
			cveID:   "not-a-cve",
			wantErr: true,
		},
		{
			name:    "invalid ID - empty string",
			baseDir: "/base",
			cveID:   "",
			wantErr: true,
		},
		{
			name:    "invalid ID - sequence is zero",
			baseDir: "/base",
			cveID:   "CVE-2024-0",
			wantErr: true,
		},
		{
			name:    "invalid ID - year is not 4 digits",
			baseDir: "/base",
			cveID:   "CVE-24-1234",
			wantErr: true,
		},
		{
			name:    "invalid ID - missing sequence",
			baseDir: "/base",
			cveID:   "CVE-2024-",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := Path(tt.baseDir, tt.cveID)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestValidateCVEID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cveID   string
		wantErr bool
	}{
		{
			name:  "valid ID",
			cveID: "CVE-2024-1234",
		},
		{
			name:  "valid ID - minimum sequence",
			cveID: "CVE-2024-1",
		},
		{
			name:  "valid ID - long sequence",
			cveID: "CVE-2024-123456",
		},
		{
			name:    "invalid - empty string",
			cveID:   "",
			wantErr: true,
		},
		{
			name:    "invalid - wrong prefix",
			cveID:   "cve-2024-1234",
			wantErr: true,
		},
		{
			name:    "invalid - year not 4 digits",
			cveID:   "CVE-24-1234",
			wantErr: true,
		},
		{
			name:  "valid - zero-padded sequence",
			cveID: "CVE-2024-0123",
		},
		{
			name:  "valid - zero-padded sequence (CVE-1999-0003)",
			cveID: "CVE-1999-0003",
		},
		{
			name:  "valid - modern CVE with zero-padded sequence (CVE-2026-0994)",
			cveID: "CVE-2026-0994",
		},
		{
			name:    "invalid - sequence is zero",
			cveID:   "CVE-2024-0",
			wantErr: true,
		},
		{
			name:    "invalid - trailing junk",
			cveID:   "CVE-2024-1234-extra",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateCVEID(tt.cveID)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestFieldPath_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		fp   FieldPath
		want string
	}{
		{
			name: "nil path",
			fp:   nil,
			want: "",
		},
		{
			name: "empty path",
			fp:   FieldPath{},
			want: "",
		},
		{
			name: "single segment",
			fp:   FieldPath{"status"},
			want: "status",
		},
		{
			name: "segment containing a dot",
			fp:   FieldPath{"a.b", "c"},
			want: "a.b.c",
		},
		{
			name: "realistic path",
			fp:   FieldPath{"releases", "2150.8.0", "auto_triage", "status"},
			want: "releases.2150.8.0.auto_triage.status",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.fp.String())
		})
	}
}

func TestFieldPath_Append(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		fp   FieldPath
		seg  string
		want FieldPath
	}{
		{
			name: "append to nil",
			fp:   nil,
			seg:  "status",
			want: FieldPath{"status"},
		},
		{
			name: "append to empty",
			fp:   FieldPath{},
			seg:  "status",
			want: FieldPath{"status"},
		},
		{
			name: "append to non-empty",
			fp:   FieldPath{"releases", "2150.8.0"},
			seg:  "status",
			want: FieldPath{"releases", "2150.8.0", "status"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.fp.Append(tt.seg)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFieldPath_Append_NoAliasing(t *testing.T) {
	t.Parallel()

	base := FieldPath{"a", "b"}
	first := base.Append("c")
	second := base.Append("d")

	// Mutations to second must not affect first.
	assert.Equal(t, FieldPath{"a", "b", "c"}, first)
	assert.Equal(t, FieldPath{"a", "b", "d"}, second)
	// Original must also be unchanged.
	assert.Equal(t, FieldPath{"a", "b"}, base)
}
