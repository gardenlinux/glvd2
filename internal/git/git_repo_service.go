package git

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"

	"github.com/gardenlinux/glvd2/internal/config"
)

type SubmoduleService struct {
	cfg *config.AppConfig
}

func NewSubmoduleService(cfg *config.AppConfig) (*SubmoduleService, error) {
	return &SubmoduleService{
		cfg: cfg,
	}, nil
}

func gitBinaryExists() bool {
	_, err := exec.LookPath("git")
	return err == nil
}

func setup(ctx context.Context) error {
	if !gitBinaryExists() {
		return errors.New("git is not available as shell command!" +
			"Maybe it is not installed or the path is not set correctly?")
	}

	cmd := exec.CommandContext(ctx, "git", "submodule", "update", "--init", "--recursive")
	cmd.Stdout = os.Stdout

	err := cmd.Run()
	if err != nil {
		return err
	}

	// ensure that we really have no local changes
	cmd = exec.CommandContext(ctx, "git", "submodule", "foreach", "--recursive", "git", "reset", "--hard")
	cmd.Stdout = os.Stdout

	err = cmd.Run()
	if err != nil {
		return err
	}

	return nil
}

// Even after the recent clean up there are still three CVEs with a wrong date format
// for now just delete them to avoid parsing issues.
// TODO: Can be removed, if dates get fixed in the repo.
func fixDateIssues() error {
	slog.Info("clean up of problematic CVEs (invalid dates)")

	problematicFiles := []string{
		"submodules/cvelistV5/cves/2022/38xxx/CVE-2022-38369.json",
		"submodules/cvelistV5/cves/2022/38xxx/CVE-2022-38370.json",
	}

	for _, file := range problematicFiles {
		err := os.Remove(file)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *SubmoduleService) GetLatest(ctx context.Context) error {
	err := setup(ctx)
	if err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, "git", "submodule", "update", "--remote")
	cmd.Stdout = os.Stdout

	err = cmd.Run()
	if err != nil {
		return err
	}

	err = fixDateIssues()
	if err != nil {
		return err
	}

	return nil
}
