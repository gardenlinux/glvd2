package debsectracker_test

import (
	"testing"

	"github.com/gardenlinux/glvd2/internal/config"
	"github.com/gardenlinux/glvd2/internal/debsectracker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerdictIndex_Lookup(t *testing.T) {
	t.Parallel()

	cfg := &config.AppConfig{
		DebSecTrackerSubRepoPath: "./testdata/verdictindextest/debsectracker",
	}
	s, _ := newTestService(t, cfg)
	require.NoError(t, s.IngestTriage(t.Context()))

	index, err := s.NewVerdictIndex(t.Context())
	require.NoError(t, err)

	tests := []struct {
		name    string
		cveID   string
		purl    string
		want    debsectracker.Verdict
		wantErr bool
	}{
		{
			name:  "concrete sid version is fixed",
			cveID: "CVE-2025-0001",
			purl:  "pkg:deb/debian/foo",
			want:  debsectracker.Verdict{Reason: debsectracker.ReasonFixed, FixedVersion: "1.2.3-4"},
		},
		{
			name:  "deb/gardenlinux-namespaces are equivalent",
			cveID: "CVE-2025-0001",
			purl:  "pkg:deb/gardenlinux/foo",
			want:  debsectracker.Verdict{Reason: debsectracker.ReasonFixed, FixedVersion: "1.2.3-4"},
		},
		{
			name:  "unfixed contains the additional unimportant info",
			cveID: "CVE-2025-0002",
			purl:  "pkg:deb/debian/bar",
			want:  debsectracker.Verdict{Reason: debsectracker.ReasonUnfixed, Info: "unimportant"},
		},
		{
			name:  "not-affected",
			cveID: "CVE-2025-0003",
			purl:  "pkg:deb/debian/baz",
			want:  debsectracker.Verdict{Reason: debsectracker.ReasonNotAffected},
		},
		{
			name:  "end-of-life",
			cveID: "CVE-2025-0004",
			purl:  "pkg:deb/debian/qux",
			want:  debsectracker.Verdict{Reason: debsectracker.ReasonEndOfLife},
		},
		{
			name:  "removed",
			cveID: "CVE-2025-0005",
			purl:  "pkg:deb/debian/removedpkg",
			want:  debsectracker.Verdict{Reason: debsectracker.ReasonRemoved},
		},
		{
			name:  "itp",
			cveID: "CVE-2025-0005",
			purl:  "pkg:deb/debian/itppkg",
			want:  debsectracker.Verdict{Reason: debsectracker.ReasonITP},
		},
		{
			name:  "undetermined",
			cveID: "CVE-2025-0005",
			purl:  "pkg:deb/debian/undetpkg",
			want:  debsectracker.Verdict{Reason: debsectracker.ReasonUndetermined},
		},
		{
			name:  "concrete version with inert low urgency info",
			cveID: "CVE-2025-0006",
			purl:  "pkg:deb/debian/quux",
			want: debsectracker.Verdict{
				Reason:       debsectracker.ReasonFixed,
				FixedVersion: "3:2.2.3-2+deb12u1",
				Info:         "low",
			},
		},
		{
			name:  "source pkg name with no sid entry is no-entry",
			cveID: "CVE-2025-0001",
			purl:  "pkg:deb/debian/unknownsource",
			want:  debsectracker.Verdict{Reason: debsectracker.ReasonNoEntry},
		},
		{
			name:  "unknown CVE is no-entry",
			cveID: "CVE-9999-0000",
			purl:  "pkg:deb/debian/foo",
			want:  debsectracker.Verdict{Reason: debsectracker.ReasonNoEntry},
		},
		{
			name:    "malformed PURL errors",
			cveID:   "CVE-2025-0001",
			purl:    "not-a-purl",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, gotErr := index.Lookup(tt.cveID, tt.purl)
			if tt.wantErr {
				require.Error(t, gotErr)
				return
			}
			require.NoError(t, gotErr)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestVerdictIndex_IgnoresStableCodenameRows proves the index derives its verdict from the unprefixed sid line,
// never from a [codename] release row.
func TestVerdictIndex_IgnoresStableCodenameRows(t *testing.T) {
	t.Parallel()

	cfg := &config.AppConfig{
		DebSecTrackerSubRepoPath: "./testdata/verdictindextest/debsectracker",
	}
	s, _ := newTestService(t, cfg)
	require.NoError(t, s.IngestTriage(t.Context()))

	index, err := s.NewVerdictIndex(t.Context())
	require.NoError(t, err)

	// CVE-2025-0001 carries a [bookworm] row at 1.2.3-2+deb12u1, but the verdict must come from the sid line (1.2.3-4).
	got, err := index.Lookup("CVE-2025-0001", "pkg:deb/debian/foo")
	require.NoError(t, err)
	assert.Equal(t, debsectracker.Verdict{Reason: debsectracker.ReasonFixed, FixedVersion: "1.2.3-4"}, got)
}
