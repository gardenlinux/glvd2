package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/gardenlinux/glvd2/internal/config"
	"github.com/stretchr/testify/assert"
)

// hasExactLine reports whether message contains line as a full, standalone line, which is
// what git trailer lookups (grep "^line$") rely on.
func hasExactLine(message, line string) bool {
	return slices.Contains(strings.Split(message, "\n"), line)
}

func TestCommitMessageForGroup(t *testing.T) {
	t.Parallel()

	cfg := &config.AppConfig{
		BaselineCommitAnchor:  "GLVD2-Baseline: true",
		LastCommitOfRunAnchor: "GLVD2-Last-Commit-Of-Run: true",
	}
	summary := runSummary{Created: 1, Updated: 2, Unchanged: 3}

	tests := []struct {
		name           string
		group          commitGroupName
		isLastCommit   bool
		wantBaseline   bool
		wantLastCommit bool
	}{
		{"assessments as last commit carries both trailers", commitGroupAssessments, true, true, true},
		{"assessments not last commit omits last-commit trailer", commitGroupAssessments, false, true, false},
		{"audit as last commit carries only last-commit trailer", commitGroupAudit, true, false, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			msg := commitMessageForGroup(string(tc.group), cfg, summary, tc.isLastCommit)
			assert.Equal(t, tc.wantBaseline, hasExactLine(msg, cfg.BaselineCommitAnchor), "baseline trailer")
			assert.Equal(t, tc.wantLastCommit, hasExactLine(msg, cfg.LastCommitOfRunAnchor), "last-commit trailer")
		})
	}
}
