package debsectracker_test

import (
	"testing"

	"github.com/gardenlinux/glvd2/internal/debsectracker"
	"github.com/stretchr/testify/assert"
)

func TestVerdictFromSid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		sidLine    string
		info       string
		want       debsectracker.Verdict
		wantStatus debsectracker.Status
	}{
		{
			name:    "concrete version is fixed",
			sidLine: "1.2.3-4",
			want: debsectracker.Verdict{
				Reason:       debsectracker.ReasonFixed,
				FixedVersion: "1.2.3-4",
			},
			wantStatus: debsectracker.StatusFixed,
		},
		{
			name:    "concrete version carries the info verbatim",
			sidLine: "2:1.0+dfsg-1",
			info:    "bug #1126266",
			want: debsectracker.Verdict{
				Reason:       debsectracker.ReasonFixed,
				FixedVersion: "2:1.0+dfsg-1",
				Info:         "bug #1126266",
			},
			wantStatus: debsectracker.StatusFixed,
		},
		{
			name:       "not-affected",
			sidLine:    "<not-affected>",
			want:       debsectracker.Verdict{Reason: debsectracker.ReasonNotAffected},
			wantStatus: debsectracker.StatusNotAffected,
		},
		{
			name:    "unfixed is affected-no-fix and keeps the inert urgency info",
			sidLine: "<unfixed>",
			info:    "unimportant",
			want: debsectracker.Verdict{
				Reason: debsectracker.ReasonUnfixed,
				Info:   "unimportant",
			},
			wantStatus: debsectracker.StatusAffectedNoFix,
		},
		{
			name:       "end-of-life is affected-no-fix",
			sidLine:    "<end-of-life>",
			want:       debsectracker.Verdict{Reason: debsectracker.ReasonEndOfLife},
			wantStatus: debsectracker.StatusAffectedNoFix,
		},
		{
			name:       "undetermined",
			sidLine:    "<undetermined>",
			want:       debsectracker.Verdict{Reason: debsectracker.ReasonUndetermined},
			wantStatus: debsectracker.StatusUndecided,
		},
		{
			name:       "itp",
			sidLine:    "<itp>",
			want:       debsectracker.Verdict{Reason: debsectracker.ReasonITP},
			wantStatus: debsectracker.StatusUndecided,
		},
		{
			name:       "removed",
			sidLine:    "<removed>",
			want:       debsectracker.Verdict{Reason: debsectracker.ReasonRemoved},
			wantStatus: debsectracker.StatusUndecided,
		},
		{
			name:       "unrecognised token",
			sidLine:    "<future-token>",
			want:       debsectracker.Verdict{Reason: debsectracker.ReasonUnknownToken},
			wantStatus: debsectracker.StatusUndecided,
		},
		{
			name:       "empty field is an unknown token",
			sidLine:    "",
			want:       debsectracker.Verdict{Reason: debsectracker.ReasonUnknownToken},
			wantStatus: debsectracker.StatusUndecided,
		},
		{
			name:    "starts not with < is a version",
			sidLine: "123.33<token>",
			want: debsectracker.Verdict{
				Reason:       debsectracker.ReasonFixed,
				FixedVersion: "123.33<token>",
			},
			wantStatus: debsectracker.StatusFixed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := debsectracker.VerdictFromSid(tc.sidLine, tc.info)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.wantStatus, got.Status())
		})
	}
}
