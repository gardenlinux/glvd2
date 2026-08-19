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

	"github.com/gardenlinux/glvd2/internal/gardenlinux/version"
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

type Package struct {
	Name         string
	Version      string
	Architecture string
}

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
		componentsStr := strings.Split(match[1], ",") //nolint:modernize // works for now
		for _, c := range componentsStr {
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
		architecturesStr := strings.Split(match[1], " ") //nolint:modernize // works for now
		for _, a := range architecturesStr {
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
			slog.Error("could not parse int",
				slog.String("value", match[2]))
			continue
		}
		packageFile.Size = size
		packageFile.PackagePath = match[3]

		result.PackageFiles = append(result.PackageFiles, packageFile)
	}

	return result, nil
}

func GetPackageListsFromInRelease(ctx context.Context, release version.GardenLinuxRelease) ([]Package, error) {
	var err error
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
		var packages []Package
		packages, err = GetPackageList(ctx, release, packagefile)
		if err != nil {
			slog.Error("could not get packages list",
				slog.Any("error", err))
			continue
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

func ParsePackageListInRelease(content string) ([]Package, error) {
	slog.Debug("Parsing package list")
	items := strings.Split(strings.TrimSpace(content), "\n\n")

	result := make([]Package, 0, 250) //nolint:mnd // just preheating array

	for _, item := range items {
		pkg := Package{}
		for _, line := range strings.Split(item, "\n") { //nolint:modernize // works for now
			if strings.HasPrefix(line, "Package: ") { //nolint:modernize // Suggested CutPrefix does not work
				pkg.Name = strings.TrimPrefix(line, "Package: ")
			}
			if strings.HasPrefix(line, "Version: ") { //nolint:modernize // Suggested CutPrefix does not work
				pkg.Version = strings.TrimPrefix(line, "Version: ")
			}
			if strings.HasPrefix(line, "Architecture: ") { //nolint:modernize // Suggested CutPrefix does not work
				pkg.Architecture = strings.TrimPrefix(line, "Architecture: ")
			}
		}

		result = append(result, pkg)
	}

	slog.With("Count", len(result)).Debug("Found packages")
	return result, nil
}
