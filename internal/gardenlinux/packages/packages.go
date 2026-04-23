package packages

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strconv"
	"strings"

	"github.com/gardenlinux/glvd2/internal/gardenlinux/version"
	"github.com/gardenlinux/glvd2/internal/whttp"
	"github.com/spf13/cobra"
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
	ComponentAll
)

//nolint:gochecknoglobals // not a global
var ArchitectureToName = map[Architecture]string{
	ArchitectureAll:   "all",
	ArchitectureAmd64: "amd64",
	ArchitectureArm64: "arm64",
}

//nolint:gochecknoglobals // not a global
var ArchitectureToEnum = map[string]Architecture{
	"all":   ArchitectureAll,
	"amd64": ArchitectureAmd64,
	"arm64": ArchitectureArm64,
}

//nolint:gochecknoglobals // not a global
var ComponentToName = map[Component]string{
	ComponentMain: "main",
}

//nolint:gochecknoglobals // not a global
var ComponentToEnum = map[string]Component{
	"main": ComponentMain,
}

// const glPackageURL = "https://packages.gardenlinux.io/gardenlinux/dists/1877.14/main/binary-amd64/Packages.gz"
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

func getInReleaseFile(release version.GardenLinuxRelease) (string, error) {
	client := whttp.NewClient()

	inreleaseURL := fmt.Sprintf(glInreleaseURL, release.Name)

	response, err := client.Get(inreleaseURL)
	if err != nil {
		slog.With("module", "packages").With("url", inreleaseURL).Error(err.Error())
		return "", err
	}

	return string(*response), nil
}

func ParseInReleaseFile(content string) (InRelease, error) {
	if len(strings.TrimSpace(content)) == 0 {
		return InRelease{}, errors.New("empty inrelease file")
	}

	result := InRelease{}

	// Regexes
	codenameRegex := regexp.MustCompile("Codename: (.*)")
	componentRegex := regexp.MustCompile("Components: (.*)")
	architectureRegex := regexp.MustCompile("Architectures: (.*)")
	packagesGzRegex := regexp.MustCompile(`(?m) ([a-zA-Z0-9]{64}) (\d+) (.*/Packages.gz)$`)

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
			tmp, ok := ComponentToEnum[c]
			if !ok {
				slog.With("component", tmp).Error("Could not map to component enum")
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
			tmp, ok := ArchitectureToEnum[a]
			if !ok {
				slog.With("architecture", tmp).Error("Could not map to architecture enum")
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
			slog.With("value", match[2]).Error("could not parse int")
			continue
		}
		packageFile.Size = size
		packageFile.PackagePath = match[3]

		result.PackageFiles = append(result.PackageFiles, packageFile)
	}

	return result, nil
}

func GetPackageLists(release version.GardenLinuxRelease) ([]Package, error) {
	var err error
	content, err := getInReleaseFile(release)
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
		packages, err = GetPackageList(release, packagefile)
		if err != nil {
			slog.Error(err.Error())
			continue
		}
		result = append(result, packages...)
	}

	return result, nil
}

func GetPackageList(release version.GardenLinuxRelease, packageFile PackageFile) ([]Package, error) {
	url := BuildPackageURL(release, packageFile)
	if url == "" {
		slog.With("release", release).With("packagefile", packageFile.PackagePath).Error("empty url")
		return []Package{}, errors.New("empty url")
	}

	slog.With("release", release).
		With("packagefile", packageFile.PackagePath).
		With("url", url).
		Info("Retrieving package list")
	client := whttp.NewClient()
	body, err := client.Get(url)
	if err != nil {
		slog.With("release", release).With("packagefile", packageFile.PackagePath).Error(err.Error())
		return []Package{}, err
	}

	reader, err := gzip.NewReader(bytes.NewReader(*body))
	if err != nil {
		return []Package{}, err
	}
	defer reader.Close() //nolint:errcheck // not necessary here

	rawPackages, err := io.ReadAll(reader)
	if err != nil {
		return []Package{}, err
	}

	packages, err := ParsePackageList(string(rawPackages))
	if err != nil {
		return []Package{}, err
	}

	return packages, nil
}

func ParsePackageList(content string) ([]Package, error) {
	slog.Debug("Parsing package list")
	items := strings.Split(strings.TrimSpace(content), "\n\n")

	result := make([]Package, 0, len(items))

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

func Cmd() (*cobra.Command, error) {
	cmd := &cobra.Command{
		Use:     "packages <version>",
		Short:   "Print packages of a <version>",
		GroupID: "debug",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, _ []string) error {
			vers, _ := cmd.Flags().GetString("version")
			release, err := version.MakeGardenLinuxReleaseFromString(vers)
			if err != nil {
				return err
			}

			packages, err := GetPackageLists(release)
			if err != nil {
				return err
			}

			for _, pkg := range packages {
				fmt.Printf("%s (%s) %s\n", pkg.Name, pkg.Architecture, pkg.Version) //nolint:revive,forbidigo,golines,lll // printing output for debugging
			}
			return nil
		},
	}
	cmd.Flags().String("version", "", "specific version")
	err := cmd.MarkFlagRequired("version")
	if err != nil {
		return nil, err
	}

	return cmd, nil
}
