package config_test

import (
	"testing"

	"github.com/gardenlinux/glvd2/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidate_AcceptsValidConfig(t *testing.T) {
	t.Parallel()

	cfg := &config.AppConfig{
		CVEListV5SubRepoPath:     "./submodules/cvelistV5",
		DebSecTrackerSubRepoPath: "./submodules/debian-security-tracker",
		InternalSqliteDBPath:     "./data/tmp/internal.sqlite",
		AuditDir:                 "./data/audit",
		AssessmentsDir:           "./data/assessments",
		BaselineCommitAnchor:     "GLVD2-Baseline: true",
		// RepoMetadataCachePath intentionally empty - it is optional.
	}
	require.NoError(t, config.Validate(cfg))
}

func TestValidate_RejectsEmptyRequiredFields(t *testing.T) {
	t.Parallel()

	full := config.AppConfig{
		CVEListV5SubRepoPath:     "./submodules/cvelistV5",
		DebSecTrackerSubRepoPath: "./submodules/debian-security-tracker",
		InternalSqliteDBPath:     "./data/tmp/internal.sqlite",
		AuditDir:                 "./data/audit",
		AssessmentsDir:           "./data/assessments",
		BaselineCommitAnchor:     "GLVD2-Baseline: true",
	}

	cases := []struct {
		name  string
		unset func(*config.AppConfig)
	}{
		{"missing CVEListV5SubRepoPath", func(c *config.AppConfig) { c.CVEListV5SubRepoPath = "" }},
		{"missing DebSecTrackerSubRepoPath", func(c *config.AppConfig) { c.DebSecTrackerSubRepoPath = "" }},
		{"missing InternalSqliteDBPath", func(c *config.AppConfig) { c.InternalSqliteDBPath = "" }},
		{"missing AuditDir", func(c *config.AppConfig) { c.AuditDir = "" }},
		{"missing AssessmentDataDir", func(c *config.AppConfig) { c.AssessmentsDir = "" }},
		{"missing BaselineCommitAnchor", func(c *config.AppConfig) { c.BaselineCommitAnchor = "" }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := full // copy
			tc.unset(&cfg)
			assert.Error(t, config.Validate(&cfg))
		})
	}
}
