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
}

// LoadAppConfig loads the configuration from disk.
func LoadAppConfig() (*AppConfig, error) {
	var cfg AppConfig

	viper.SetConfigName("default")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./config")

	err := viper.ReadInConfig()
	if err != nil {
		return nil, err
	}

	err = viper.Unmarshal(&cfg)
	if err != nil {
		wErr := fmt.Errorf("failure while loading the configuration: %w", err)
		return nil, wErr
	}

	return &cfg, nil
}
