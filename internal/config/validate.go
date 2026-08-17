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
		{cfg.AssessmentDataDir, "assessment_data_dir"},
		{cfg.BaselineCommitAnchor, "baseline_commit_anchor"},
	}
	var errs []error
	for _, f := range required {
		if f.value == "" {
			errs = append(errs, fmt.Errorf("%s is required", f.name))
		}
	}

	return errors.Join(errs...)
}
