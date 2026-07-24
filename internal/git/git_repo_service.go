package git

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"

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

// runGit executes a git command and returns a wrapped error including stderr on failure.
func runGit(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "git", args...) //nolint:gosec // private function with only hard-coded values

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("git %s: %w (stderr: %s)", args[0], err, strings.TrimSpace(stderr.String()))
	}

	if stdout.Len() > 0 {
		slog.Debug("git output", slog.String("cmd", strings.Join(args, " ")), slog.String("stdout", stdout.String()))
	}

	return nil
}

func setup(ctx context.Context) error {
	if !gitBinaryExists() {
		return errors.New("git is not available as shell command; " +
			"maybe it is not installed or the path is not set correctly")
	}

	// ensure that we really have no local changes
	if err := runGit(ctx, "submodule", "foreach", "--recursive", "git", "reset", "--hard"); err != nil {
		return fmt.Errorf("resetting submodules: %w", err)
	}

	// use the blob:none filter in the submodules
	if err := runGit(ctx, "config", "clone.filterSubmodules", "true"); err != nil {
		return fmt.Errorf("configuring submodule filter: %w", err)
	}

	if err := runGit(ctx, "submodule", "update", "--init", "--recursive", "--filter=blob:none"); err != nil {
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
	if err = runGit(ctx, "submodule", "update", "--remote"); err != nil {
		return fmt.Errorf("updating submodules: %w", err)
	}

	err = fixDateIssues()
	if err != nil {
		return err
	}

	slog.Info("Finished updating the git submodules")

	return nil
}
