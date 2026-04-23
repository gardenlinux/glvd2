package version

import (
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/gardenlinux/glvd2/internal/gardenlinux/glrd"
)

type GardenLinuxRelease struct {
	Name   string
	Major  int
	Minor  int
	Patch  int
	SemVer bool
}

func (g *GardenLinuxRelease) Format() string {
	if g.SemVer {
		return fmt.Sprintf("%d.%d.%d", g.Major, g.Minor, g.Patch)
	}

	return fmt.Sprintf("%d.%d", g.Major, g.Minor)
}

func (g *GardenLinuxRelease) ParseFromGlrdVersion(version glrd.Version) error {
	g.Major = version.Major
	g.Minor = version.Minor
	g.Patch = version.Patch
	g.SemVer = true // TODO: check how version.Patch is defined before release 20xx

	g.Name = fmt.Sprintf("%d.%d.%d", g.Major, g.Minor, g.Patch)

	return nil
}

func (g *GardenLinuxRelease) ParseFromString(name string) error {
	var err error

	g.Name = name
	g.SemVer = false

	parts := strings.Split(g.Name, ".")
	partsCount := len(parts)

	// Santity check
	if partsCount < 2 || partsCount > 3 {
		slog.With("name", name).With("parts", partsCount).Error("invalid version schema")
		return errors.New("invalid version schema")
	}

	// Major and Minor
	if partsCount >= 2 { //nolint:mnd // It's two parts
		g.SemVer = false
		g.Major, err = strconv.Atoi(parts[0])
		if err != nil {
			slog.With("name", name).Error("could not convert part 0 (major) to integer")
			return err
		}
		g.Minor, err = strconv.Atoi(parts[1])
		if err != nil {
			slog.With("name", name).Error("could not convert part 1 (minor) to integer")
			return err
		}
	}

	// releases prior 2017.0.0 were not semver (x.y), since 2017.0.0 semver is used (x.y.z)
	if g.Major >= 2017 && partsCount != 3 {
		slog.With("name", name).Error("mismatch with semver parts post 2017.x.x")
		return errors.New("semver version schema expects three version parts")
	}
	if g.Major < 2017 && partsCount != 2 {
		slog.With("name", name).Error("mismatch with semver parts prior 2017.x.x")
		return errors.New("prior semver version expects only two version parts")
	}

	// Patch (if applicable)
	if partsCount == 3 { //nolint:mnd // It's three parts
		g.SemVer = true
		g.Patch, err = strconv.Atoi(parts[2])
		if err != nil {
			slog.With("name", name).Error("could not convert part 2 (patch) to integer")
			return err
		}
	}

	return nil
}
