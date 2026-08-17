package config

import (
	"fmt"

	"github.com/spf13/viper"
)

// AppConfig contains different configuration options for the application.
type AppConfig struct {
	CVEListV5SubRepoPath     string `mapstructure:"cve_list_v5_sub_repo_path"`
	DebSecTrackerSubRepoPath string `mapstructure:"deb_sec_tracker_sub_repo_path"`
	InternalSqliteDBPath     string `mapstructure:"internal_sqlite_db_path"`
	RepoMetadataCachePath    string `mapstructure:"repo_metadata_cache_path"`
	AuditDir                 string `mapstructure:"audit_dir"`
	AssessmentDataDir        string `mapstructure:"assessment_data_dir"`
	BaselineCommitAnchor     string `mapstructure:"baseline_commit_anchor"`
}

// LoadAppConfig loads the configuration from the given directory.
func LoadAppConfig(configDir string) (*AppConfig, error) {
	v := viper.New()
	v.AddConfigPath(configDir)
	v.SetConfigName("default")
	v.SetConfigType("yaml")

	v.SetDefault("cve_list_v5_sub_repo_path", "./submodules/cvelistV5")
	v.SetDefault("deb_sec_tracker_sub_repo_path", "./submodules/debian-security-tracker")
	v.SetDefault("internal_sqlite_db_path", "./data/tmp/internal.sqlite")
	v.SetDefault("repo_metadata_cache_path", "./data/tmp/metadata")
	v.SetDefault("audit_dir", "./data/audit")
	v.SetDefault("assessment_data_dir", "./data/assessments")
	v.SetDefault("baseline_commit_anchor", "GLVD2-Baseline: true")

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	var cfg AppConfig
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshalling config: %w", err)
	}

	if err := Validate(&cfg); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &cfg, nil
}
