package version

import (
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/gardenlinux/glvd2/internal/gardenlinux/glrd"
)

// GardenlinuxVersionParts: Versioning scheme before 2017.0.0.
const GardenlinuxVersionParts = 2

// GardenlinuxSemverParts: Versioning scheme after including 2017.0.0.
const GardenlinuxSemverParts = 3

type GardenLinuxRelease struct {
	Name   string
	Major  int
	Minor  int
	Patch  int
	SemVer bool
}

func MakeGardenLinuxRelease(version glrd.Version) GardenLinuxRelease {
	release := GardenLinuxRelease{}
	release.parseFromGlrdVersion(version)
	return release
}

func MakeGardenLinuxReleaseFromString(version string) (GardenLinuxRelease, error) {
	release := GardenLinuxRelease{}
	err := release.parseFromString(version)
	if err != nil {
		return GardenLinuxRelease{}, err
	}

	return release, nil
}

func (g *GardenLinuxRelease) Format() string {
	if g.SemVer {
		return fmt.Sprintf("%d.%d.%d", g.Major, g.Minor, g.Patch)
	}

	return fmt.Sprintf("%d.%d", g.Major, g.Minor)
}

func (g *GardenLinuxRelease) parseFromGlrdVersion(version glrd.Version) {
	g.Major = version.Major
	g.Minor = version.Minor
	g.Patch = version.Patch
	g.SemVer = true // TODO: check how version.Patch is defined before release 20xx

	g.Name = fmt.Sprintf("%d.%d.%d", g.Major, g.Minor, g.Patch)
}

func (g *GardenLinuxRelease) parseFromString(name string) error {
	var err error

	g.Name = name
	g.SemVer = false

	parts := strings.Split(g.Name, ".")
	partsCount := len(parts)

	// Santity check
	if partsCount < GardenlinuxVersionParts || partsCount > GardenlinuxSemverParts {
		slog.Error("invalid version schema",
			slog.String("name", name),
			slog.Int("parts", partsCount))
		return errors.New("invalid version schema")
	}

	// Major and Minor
	if partsCount >= GardenlinuxVersionParts {
		g.SemVer = false
		g.Major, err = strconv.Atoi(parts[0])
		if err != nil {
			slog.Error("could not convert part 0 (major) to integer",
				slog.String("name", name),
				slog.String("part", parts[0]))
			return err
		}
		g.Minor, err = strconv.Atoi(parts[1])
		if err != nil {
			slog.Error("could not convert part 1 (minor) to integer",
				slog.String("name", name),
				slog.String("part", parts[1]))
			return err
		}
	}

	// releases prior 2017.0.0 were not semver (x.y), since 2017.0.0 semver is used (x.y.z)
	if g.Major >= 2017 && partsCount != GardenlinuxSemverParts {
		slog.Error("mismatch with semver parts post 2017.x.x",
			slog.String("name", name),
			slog.Int("partsCount", partsCount))
		return errors.New("semver version schema expects three version parts")
	}
	if g.Major < 2017 && partsCount != GardenlinuxVersionParts {
		slog.Error("mismatch with semver parts prior 2017.x.x",
			slog.String("name", name),
			slog.Int("partsCount", partsCount))
		return errors.New("prior semver version expects only two version parts")
	}

	// Patch (if applicable)
	if partsCount == GardenlinuxSemverParts {
		g.SemVer = true
		g.Patch, err = strconv.Atoi(parts[2])
		if err != nil {
			slog.Error("could not convert part 2 (patch) to integer",
				slog.String("name", name),
				slog.String("part", parts[2]))
			return err
		}
	}

	return nil
}
