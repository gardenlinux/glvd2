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

	"github.com/gardenlinux/glvd2/internal/client/http"
	"github.com/gardenlinux/glvd2/internal/types"

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

var architectureToName = map[Architecture]string{
	ArchitectureAll:   "all",
	ArchitectureAmd64: "amd64",
	ArchitectureArm64: "arm64",
}

var architectureToEnum = map[string]Architecture{
	"all":   ArchitectureAll,
	"amd64": ArchitectureAmd64,
	"arm64": ArchitectureArm64,
}

var componentToName = map[Component]string{
	ComponentMain: "main",
}

var componentToEnum = map[string]Component{
	"main": ComponentMain,
}

// const GL_PACKAGE_URL = "https://packages.gardenlinux.io/gardenlinux/dists/1877.14/main/binary-amd64/Packages.gz"
//
// Parameters:
// 0: 1877.14, today => Suite
// 1: main/binary-amd64/Packages.gz => PackagePath
const GL_PACKAGE_URL = "https://packages.gardenlinux.io/gardenlinux/dists/%s/%s"

// Parameters
// 0: 1877.14, today => Suite
const GL_INRELEASE_URL = "https://packages.gardenlinux.io/gardenlinux/dists/%s/InRelease"

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
	Codename      types.GardenLinuxRelease // aka Version, Release, Suite
	Components    []Component
	Architectures []Architecture
	PackageFiles  []PackageFile
}

func buildPackageUrl(release types.GardenLinuxRelease, packageFile PackageFile) string {
	return fmt.Sprintf(GL_PACKAGE_URL, release.Name, packageFile.PackagePath)
}

func getInReleaseFile(release types.GardenLinuxRelease) (string, error) {
	client := http.NewClient()

	inrelease_url := fmt.Sprintf(GL_INRELEASE_URL, release.Name)

	response, err := client.Get(inrelease_url)
	if err != nil {
		slog.With("module", "packages").With("url", inrelease_url).Error(err.Error())
		return "", err
	}

	return string(*response), nil
}

func parseInReleaseFile(content string) (InRelease, error) {
	if len(strings.TrimSpace(content)) == 0 {
		return InRelease{}, errors.New("empty inrelease file")
	}

	result := InRelease{}

	// Regex Codename
	codenameRegex, err := regexp.Compile("Codename: (.*)")
	if err != nil {
		return result, err
	}

	componentRegex, err := regexp.Compile("Components: (.*)")
	if err != nil {
		return result, err
	}

	architectureRegex, err := regexp.Compile("Architectures: (.*)")
	if err != nil {
		return result, err
	}

	packagesGzRegex, err := regexp.Compile(`(?m) ([a-zA-Z0-9]{64}) (\d+) (.*/Packages.gz)$`)
	if err != nil {
		return result, err
	}

	//
	// Extracting values
	//
	var match []string

	// Codename
	match = codenameRegex.FindStringSubmatch(content)
	if match != nil {
		glr := types.GardenLinuxRelease{}
		err := glr.ParseFromString(match[1])
		if err != nil {
			return result, err
		}
		result.Codename = glr
	}

	// Component
	match = componentRegex.FindStringSubmatch(content)
	if match != nil {
		componentsStr := strings.Split(match[1], ",")
		for _, c := range componentsStr {
			tmp, ok := componentToEnum[c]
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
		architecturesStr := strings.Split(match[1], " ")
		for _, a := range architecturesStr {
			tmp, ok := architectureToEnum[a]
			if !ok {
				slog.With("architecture", tmp).Error("Could not map to architecture enum")
				continue
			}
			result.Architectures = append(result.Architectures, tmp)
		}
	}

	// Packages.gz files
	var matches [][]string
	matches = packagesGzRegex.FindAllStringSubmatch(content, -1)
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

func GetPackageLists(release types.GardenLinuxRelease) ([]Package, error) {
	content, err := getInReleaseFile(release)
	if err != nil {
		return nil, err
	}

	inrelease, err := parseInReleaseFile(content)
	if err != nil {
		return nil, err
	}

	var result []Package

	for _, packagefile := range inrelease.PackageFiles {
		packages, err := GetPackageList(release, packagefile)
		if err != nil {
			slog.Error(err.Error())
			continue
		}
		result = append(result, packages...)
	}

	return result, nil
}

func GetPackageList(release types.GardenLinuxRelease, packageFile PackageFile) ([]Package, error) {
	url := buildPackageUrl(release, packageFile)
	if url == "" {
		slog.With("release", release).With("packagefile", packageFile.PackagePath).Error("empty url")
		return []Package{}, errors.New("empty url")
	}

	slog.With("release", release).With("packagefile", packageFile.PackagePath).With("url", url).Info("Retrieving package list")
	client := http.NewClient()
	body, err := client.Get(url)
	if err != nil {
		slog.With("release", release).With("packagefile", packageFile.PackagePath).Error(err.Error())
		return []Package{}, err
	}

	reader, err := gzip.NewReader(bytes.NewReader(*body))
	if err != nil {
		return []Package{}, err
	}
	defer reader.Close()

	raw_packages, err := io.ReadAll(reader)
	if err != nil {
		return []Package{}, err
	}

	//fmt.Println(string(raw_packages))

	packages, err := parsePackageList(string(raw_packages))
	if err != nil {
		return []Package{}, err
	}

	return packages, nil
}

func parsePackageList(content string) ([]Package, error) {
	slog.Debug("Parsing package list")
	items := strings.Split(strings.TrimSpace(content), "\n\n")

	result := []Package{}

	for _, item := range items {
		pkg := Package{}
		for _, line := range strings.Split(item, "\n") {
			if strings.HasPrefix(line, "Package: ") {
				pkg.Name = strings.TrimPrefix(line, "Package: ")
			}
			if strings.HasPrefix(line, "Version: ") {
				pkg.Version = strings.TrimPrefix(line, "Version: ")
			}
			if strings.HasPrefix(line, "Architecture: ") {
				pkg.Architecture = strings.TrimPrefix(line, "Architecture: ")
			}
		}
		// fmt.Println("---------------")
		// fmt.Println(item)
		// fmt.Println("---------------")
		result = append(result, pkg)
	}

	slog.With("Count", len(result)).Debug("Found packages")
	return result, nil
}

func PackagesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "packages <version>",
		Short: "Print packages of a <version>",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			version, _ := cmd.Flags().GetString("version")
			release := types.GardenLinuxRelease{}
			release.ParseFromString(version)

			packages, err := GetPackageLists(release)
			if err != nil {
				return err
			}

			for _, pkg := range packages {
				fmt.Printf("%s (%s) %s\n", pkg.Name, pkg.Architecture, pkg.Version)
			}
			return nil
		},
	}
	cmd.Flags().String("version", "", "specific version")
	cmd.MarkFlagRequired("version")
	return cmd
}
