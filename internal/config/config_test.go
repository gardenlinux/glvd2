package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

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
	assert.NotEmpty(t, cfg.AssessmentsDir)
	assert.NotEmpty(t, cfg.BaselineCommitAnchor)
	assert.NotEmpty(t, cfg.LastCommitOfRunAnchor)
	assert.NotEmpty(t, cfg.GLRDReleasesURL)
	assert.Equal(t, 24*time.Hour, cfg.Screening.EscalationWindow)
}

func TestLoadAppConfig_PathDefaults(t *testing.T) {
	t.Parallel()

	fallbackDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(fallbackDir, "default.yaml"), []byte("{}\n"), 0o600))

	for _, dir := range []string{"../../config", fallbackDir} {
		s, err := config.LoadAppConfig(dir)
		require.NoError(t, err)

		assert.Equal(t, "./_submodules/cvelistV5", s.CVEListV5SubRepoPath)
		assert.Equal(t, "./_submodules/debian-security-tracker", s.DebSecTrackerSubRepoPath)
		assert.Equal(t, "./_data/tmp/internal.sqlite", s.InternalSqliteDBPath)
		assert.Equal(t, "./_data/pkg-build", s.PkgBuildStoreDir)
		assert.Equal(t, "./_data/audit", s.AuditDir)
		assert.Equal(t, "./_data/assessments", s.AssessmentsDir)
		assert.Equal(t, "./_data/site", s.SiteOutDir)
	}
}

func TestLoadAppConfig_PathOverrides(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	content := `cve_list_v5_sub_repo_path: custom/cves
deb_sec_tracker_sub_repo_path: custom/tracker
internal_sqlite_db_path: custom/database.sqlite
pkgbuild_store_dir: custom/builds
audit_dir: custom/evidence
assessments_dir: custom/records
site_out_dir: custom/html
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "default.yaml"), []byte(content), 0o600))

	s, err := config.LoadAppConfig(dir)
	require.NoError(t, err)

	assert.Equal(t, "custom/cves", s.CVEListV5SubRepoPath)
	assert.Equal(t, "custom/tracker", s.DebSecTrackerSubRepoPath)
	assert.Equal(t, "custom/database.sqlite", s.InternalSqliteDBPath)
	assert.Equal(t, "custom/builds", s.PkgBuildStoreDir)
	assert.Equal(t, "custom/evidence", s.AuditDir)
	assert.Equal(t, "custom/records", s.AssessmentsDir)
	assert.Equal(t, "custom/html", s.SiteOutDir)
}
