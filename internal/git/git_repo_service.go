package git

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
)

type SubmoduleService struct{}

func NewSubmoduleService() *SubmoduleService {
	return &SubmoduleService{}
}

func gitBinaryExists() bool {
	_, err := exec.LookPath("git")
	return err == nil
}

func setup(ctx context.Context) error {
	if !gitBinaryExists() {
		return errors.New("git is not available as shell command; " +
			"maybe it is not installed or the path is not set correctly")
	}

	// all git commands for the submodule service use "." as the working directory

	// ensure that we really have no local changes
	if err := Run(ctx, ".", "submodule", "foreach", "--recursive", "git", "reset", "--hard"); err != nil {
		return fmt.Errorf("resetting submodules: %w", err)
	}

	// use the blob:none filter in the submodules
	if err := Run(ctx, ".", "config", "clone.filterSubmodules", "true"); err != nil {
		return fmt.Errorf("configuring submodule filter: %w", err)
	}

	if err := Run(ctx, ".", "submodule", "update", "--init", "--recursive", "--filter=blob:none"); err != nil {
		return fmt.Errorf("initializing submodules: %w", err)
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
	slog.Info("Setup of git submodules")
	err := setup(ctx)
	if err != nil {
		return err
	}

	slog.Info("Start updating the git submodules")
	if err = Run(ctx, ".", "submodule", "update", "--remote"); err != nil {
		return fmt.Errorf("updating submodules: %w", err)
	}

	err = fixDateIssues()
	if err != nil {
		return err
	}

	slog.Info("Finished updating the git submodules")

	return nil
}
