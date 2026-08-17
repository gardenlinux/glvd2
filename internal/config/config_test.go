package config_test

import (
	"testing"

	"github.com/gardenlinux/glvd2/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadAppConfig_RealFile(t *testing.T) {
	t.Parallel()

	// LoadAppConfig resolves the config file relative to the given dir.
	// Point it at the project root's config directory.
	cfg, err := config.LoadAppConfig("../../config")
	require.NoError(t, err)

	assert.NotEmpty(t, cfg.CVEListV5SubRepoPath)
	assert.NotEmpty(t, cfg.DebSecTrackerSubRepoPath)
	assert.NotEmpty(t, cfg.InternalSqliteDBPath)
	assert.NotEmpty(t, cfg.AuditDir)
	assert.NotEmpty(t, cfg.AssessmentDataDir)
	assert.NotEmpty(t, cfg.BaselineCommitAnchor)
}
