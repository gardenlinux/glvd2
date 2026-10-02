package config

import (
	"errors"
	"fmt"
)

// Validate checks that all required fields are non-empty.
// RepoMetadataCachePath is optional - empty means caching is disabled.
func Validate(cfg *AppConfig) error {
	required := []struct{ value, name string }{
		{cfg.CVEListV5SubRepoPath, "cve_list_v5_sub_repo_path"},
		{cfg.DebSecTrackerSubRepoPath, "deb_sec_tracker_sub_repo_path"},
		{cfg.InternalSqliteDBPath, "internal_sqlite_db_path"},
		{cfg.AuditDir, "audit_dir"},
		{cfg.AssessmentsDir, "assessments_dir"},
		{cfg.BaselineCommitAnchor, "baseline_commit_anchor"},
		{cfg.GLRDReleasesURL, "glrd_releases_url"},
	}
	var errs []error
	for _, f := range required {
		if f.value == "" {
			errs = append(errs, fmt.Errorf("%s is required", f.name))
		}
	}

	if cfg.Screening.EscalationWindow <= 0 {
		errs = append(
			errs,
			fmt.Errorf("screening.escalation_window must be positive, got %s", cfg.Screening.EscalationWindow),
		)
	}

	return errors.Join(errs...)
}
