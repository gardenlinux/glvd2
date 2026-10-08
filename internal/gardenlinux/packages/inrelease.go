package packages

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strconv"
	"strings"

	"github.com/gardenlinux/glvd2/internal/debian"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/version"
	"github.com/gardenlinux/glvd2/internal/purl"
	"github.com/gardenlinux/glvd2/internal/whttp"
)

type Component int

type Architecture int

const (
	ArchitectureAll Architecture = iota
	ArchitectureAmd64
	ArchitectureArm64
)

const (
	ComponentMain Component = iota
)

var (
	codenameRegex     = regexp.MustCompile("Codename: (.*)")
	componentRegex    = regexp.MustCompile("Components: (.*)")
	architectureRegex = regexp.MustCompile("Architectures: (.*)")
	packagesGzRegex   = regexp.MustCompile(`(?m) ([a-zA-Z0-9]{64}) (\d+) (.*/Packages.gz)$`)
	sourceFieldRegex  = regexp.MustCompile(`^([^\s(]+)(?:\s*\(([^)]*)\))?`)
)

func (a Architecture) String() string {
	switch a {
	case ArchitectureAll:
		return "all"
	case ArchitectureAmd64:
		return "amd64"
	case ArchitectureArm64:
		return "arm64"
	default:
		return "unknown architecture"
	}
}

func parseArchitecture(s string) (Architecture, bool) {
	switch s {
	case "all":
		return ArchitectureAll, true
	case "amd64":
		return ArchitectureAmd64, true
	case "arm64":
		return ArchitectureArm64, true
	default:
		return 0, false
	}
}

func (c Component) String() string {
	switch c {
	case ComponentMain:
		return "main"
	default:
		return "unknown component"
	}
}

// parseComponent maps a Debian component name to its enum value.
// Component currently has a single member; the Component result is kept for
// symmetry with parseArchitecture and to stay open to future components.
//
//nolint:unparam // single-member enum today; return kept for future components
func parseComponent(s string) (Component, bool) {
	switch s {
	case "main":
		return ComponentMain, true
	default:
		return 0, false
	}
}

// fully debian style url: https://packages.gardenlinux.io/gardenlinux/dists/1877.14/main/binary-amd64/Packages.gz
//
// Parameters:
// 0: 1877.14, today => Suite
// 1: main/binary-amd64/Packages.gz => PackagePath
const glPackageURL = "https://packages.gardenlinux.io/gardenlinux/dists/%s/%s"

// Parameters
// 0: 1877.14, today => Suite
const glInreleaseURL = "https://packages.gardenlinux.io/gardenlinux/dists/%s/InRelease"

type PackageFile struct {
	Sha256Sum   string
	Size        uint64
	PackagePath string
}

type InRelease struct {
	Codename      version.GardenLinuxRelease // aka Version, Release, Suite
	Components    []Component
	Architectures []Architecture
	PackageFiles  []PackageFile
}

func BuildPackageURL(release version.GardenLinuxRelease, packageFile PackageFile) string {
	return fmt.Sprintf(glPackageURL, release.Name, packageFile.PackagePath)
}

func getInReleaseFile(ctx context.Context, release version.GardenLinuxRelease) (string, error) {
	client := whttp.NewClient()

	inreleaseURL := fmt.Sprintf(glInreleaseURL, release.Name)

	response, _, err := client.GetString(ctx, inreleaseURL)
	if err != nil {
		slog.Error("could not get InRelease file",
			slog.Any("error", err),
			slog.String("url", inreleaseURL))
		return "", err
	}

	return response, nil
}

func ParseInReleaseFile(content string) (InRelease, error) {
	if len(strings.TrimSpace(content)) == 0 {
		return InRelease{}, errors.New("empty inrelease file")
	}

	result := InRelease{}

	//
	// Extracting values
	//
	var match []string

	// Codename
	match = codenameRegex.FindStringSubmatch(content)
	if match != nil {
		glr, err := version.MakeGardenLinuxReleaseFromString(match[1])
		if err != nil {
			return result, err
		}
		result.Codename = glr
	}

	// Component
	match = componentRegex.FindStringSubmatch(content)
	if match != nil {
		for c := range strings.SplitSeq(match[1], ",") {
			tmp, ok := parseComponent(c)
			if !ok {
				slog.Error("Could not map to component enum",
					slog.Any("component", tmp))
				continue
			}
			result.Components = append(result.Components, tmp)
		}
	}

	// Architectures
	match = architectureRegex.FindStringSubmatch(content)
	if match != nil {
		for a := range strings.SplitSeq(match[1], " ") {
			tmp, ok := parseArchitecture(a)
			if !ok {
				slog.Error("Could not map to architecture enum",
					slog.Any("architecture", tmp))
				continue
			}
			result.Architectures = append(result.Architectures, tmp)
		}
	}

	// Packages.gz files
	matches := packagesGzRegex.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		packageFile := PackageFile{Sha256Sum: match[1]}
		size, err := strconv.ParseUint(match[2], 10, 32)
		if err != nil {
			return result, fmt.Errorf("parsing Packages.gz size %q: %w", match[2], err)
		}
		packageFile.Size = size
		packageFile.PackagePath = match[3]

		result.PackageFiles = append(result.PackageFiles, packageFile)
	}

	return result, nil
}

func GetPackageListsFromInRelease(ctx context.Context, release version.GardenLinuxRelease) ([]Package, error) {
	content, err := getInReleaseFile(ctx, release)
	if err != nil {
		return nil, err
	}

	inrelease, err := ParseInReleaseFile(content)
	if err != nil {
		return nil, err
	}

	var result []Package
	for _, packagefile := range inrelease.PackageFiles {
		packages, listErr := GetPackageList(ctx, release, packagefile)
		if listErr != nil {
			return nil, fmt.Errorf("getting package list %q: %w", packagefile.PackagePath, listErr)
		}
		result = append(result, packages...)
	}

	return result, nil
}

func GetPackageList(
	ctx context.Context,
	release version.GardenLinuxRelease,
	packageFile PackageFile,
) ([]Package, error) {
	url := BuildPackageURL(release, packageFile)
	if url == "" {
		slog.Error("empty url",
			slog.Any("release", release),
			slog.String("packagefile", packageFile.PackagePath))
		return nil, errors.New("empty url")
	}

	slog.Info("Retrieving package list",
		slog.Any("release", release),
		slog.String("packagefile", packageFile.PackagePath),
		slog.String("url", url))
	client := whttp.NewClient()
	body, _, err := client.GetRaw(ctx, url)
	if err != nil {
		slog.Error("could not retrieve package list",
			slog.Any("release", release),
			slog.String("packagefile", packageFile.PackagePath),
			slog.Any("error", err))
		return nil, err
	}

	reader, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer reader.Close() //nolint:errcheck // not necessary here

	rawPackages, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	return ParsePackageListInRelease(string(rawPackages))
}

// parseSourceField extracts the source name and optional source version from a Debian "Source:" value.
func parseSourceField(value string) (string, string, error) {
	match := sourceFieldRegex.FindStringSubmatch(strings.TrimSpace(value))
	if match == nil {
		return "", "", fmt.Errorf("invalid source field %q", value)
	}

	return match[1], match[2], nil
}

// parseParagraph parses one deb822 paragraph into a Package. Every line must be
// a recognized "key: value" field or a folded continuation (leading space or tab);
// anything else is a structural error. Duplicate fields are rejected.
func parseParagraph(item string) (Package, error) {
	pkg := Package{Namespace: purl.NamespaceGardenLinux}
	seen := make(map[string]bool)
	var lastKey string

	for line := range strings.SplitSeq(item, "\n") {
		if line == "" {
			continue
		}
		// A folded continuation line starts with a space or tab and belongs to the previous field.
		if line[0] == ' ' || line[0] == '\t' {
			if lastKey == "" {
				return Package{}, fmt.Errorf("continuation line with no preceding field: %q", line)
			}
			continue
		}

		key, value, ok := strings.Cut(line, ": ")
		if !ok {
			return Package{}, fmt.Errorf("malformed field line: %q", line)
		}

		// deb822 field names are case-insensitive.
		key = strings.ToLower(key)
		if seen[key] {
			return Package{}, fmt.Errorf("duplicate field %q", key)
		}
		seen[key] = true
		lastKey = key

		switch key {
		case "package":
			pkg.Name = value
		case "source":
			source, sourceVersion, err := parseSourceField(value)
			if err != nil {
				return Package{}, err
			}
			pkg.Source, pkg.SourceVersion = source, sourceVersion
		case "version":
			pkg.Version = value
		case "architecture":
			pkg.Architecture = value
		}
	}

	return pkg, nil
}

// validatePackage enforces the structural invariants of a parsed Package:
// required fields are present and non-empty, and names match the Debian
// grammar. Version and Architecture value grammar is validated later, where
// they are consumed.
func validatePackage(pkg *Package) error {
	if err := debian.ValidatePackageName(pkg.Name); err != nil {
		return fmt.Errorf("invalid Package name %q: %w", pkg.Name, err)
	}

	if pkg.Version == "" {
		return fmt.Errorf("package %q is missing a Version field", pkg.Name)
	}

	if pkg.Architecture == "" {
		return fmt.Errorf("package %q is missing an Architecture field", pkg.Name)
	}

	// An explicit source version appears only when it differs from the binary version.
	// Absent means by definition that they are equal.
	if pkg.SourceVersion == "" {
		pkg.SourceVersion = pkg.Version
	}

	// An absent Source field means the source name equals the binary name.
	if pkg.Source == "" {
		pkg.Source = pkg.Name
		return nil
	}

	if err := debian.ValidatePackageName(pkg.Source); err != nil {
		return fmt.Errorf("invalid Source name %q for package %q: %w", pkg.Source, pkg.Name, err)
	}

	return nil
}

func ParsePackageListInRelease(content string) ([]Package, error) {
	slog.Debug("Parsing package list")
	const assumedPackageCount = 3500
	result := make([]Package, 0, assumedPackageCount)

	for item := range strings.SplitSeq(strings.TrimSpace(content), "\n\n") {
		if strings.TrimSpace(item) == "" {
			continue // formatting gap, not a package paragraph
		}

		pkg, err := parseParagraph(item)
		if err != nil {
			return nil, err
		}
		if vErr := validatePackage(&pkg); vErr != nil {
			return nil, vErr
		}

		result = append(result, pkg)
	}

	slog.With("Count", len(result)).Debug("Found packages")

	return result, nil
}
