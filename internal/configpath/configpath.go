// Package configpath defines the SafePath type used to identify config files
// by their filesystem path, and declares their default paths.
package configpath

// SafePath is a typed string representing a filesystem path to a config file.
// Using a distinct type prevents accidental plain-string paths from being passed
// where a validated config path is expected.
type SafePath string

const (
	DefaultPackageIDFilterConfigPath     SafePath = "./config/package_id_filter.toml"
	DefaultCPEFilterConfigPath           SafePath = "./config/cpe_filter.toml"
	DefaultVendorProductFilterConfigPath SafePath = "./config/vendor_product_filter.toml"
	DefaultGLSpecificMappingConfigPath   SafePath = "./config/gl_specific_packages.toml"
)
