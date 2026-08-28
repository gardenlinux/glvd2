// Package gittest provides shared helpers for tests that exercise real git repositories
// via the git binary. It is intended for use from _test.go files only.
package gittest

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	dirPerm  = 0o755
	filePerm = 0o644
)

// Env returns the minimal environment for isolated git operations. It suppresses
// global and system config, so local settings like gpg signing, commit
// templates, or hooks cannot interfere with tests.
func Env() []string {
	return []string{
		"HOME=/dev/null",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_AUTHOR_NAME=Test",
		"GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Test",
		"GIT_COMMITTER_EMAIL=test@example.com",
	}
}

// Run executes a git command in dir with the isolated environment.
// Returns stderr for the underlying git errors.
func Run(t *testing.T, dir string, args ...string) string {
	t.Helper()

	cmd := exec.CommandContext(t.Context(), "git", args...) //nolint:gosec // test-only, args are test-controlled
	cmd.Dir = dir
	cmd.Env = Env()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	require.NoError(t, err, "git %s\nstderr: %s", strings.Join(args, " "), stderr.String())

	return stdout.String()
}

// InitRepo creates a new, isolated git repository in a temporary directory and returns its path.
func InitRepo(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()

	Run(t, dir, "init", "-b", "main")
	Run(t, dir, "config", "user.name", "Test")
	Run(t, dir, "config", "user.email", "test@example.com")
	Run(t, dir, "config", "commit.gpgsign", "false")

	return dir
}

// InitBareRemote creates an isolated bare repository to act as a push remote and returns its path.
func InitBareRemote(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	Run(t, dir, "init", "--bare")

	return dir
}

// HeadSHA returns the full SHA of the current HEAD commit in dir.
func HeadSHA(t *testing.T, dir string) string {
	t.Helper()

	return strings.TrimSpace(Run(t, dir, "rev-parse", "HEAD"))
}

// GetCommitSubjects returns commit subject lines from newest to oldest in dir.
func GetCommitSubjects(t *testing.T, dir string) []string {
	t.Helper()

	out := strings.TrimSpace(Run(t, dir, "log", "--format=%s"))
	if out == "" {
		return nil
	}

	return strings.Split(out, "\n")
}

// AddEmptyCommit creates an empty commit with the given message and returns the full commit SHA.
func AddEmptyCommit(t *testing.T, dir, message string) string {
	t.Helper()

	Run(t, dir, "commit", "--allow-empty", "-m", message)

	return HeadSHA(t, dir)
}

// StageAllAndCommit stages all changes (including deletions) and commits with the given message
// and returns the full commit SHA.
func StageAllAndCommit(t *testing.T, dir, message string) string {
	t.Helper()

	Run(t, dir, "add", "-A")
	Run(t, dir, "commit", "-m", message)

	return HeadSHA(t, dir)
}

// WriteFile creates or overwrites a file relative to dir, creating any required parent
// directories automatically.
func WriteFile(t *testing.T, dir, rel, content string) {
	t.Helper()

	full := filepath.Join(dir, rel)
	require.NoError(t, os.MkdirAll(filepath.Dir(full), dirPerm))
	require.NoError(t, os.WriteFile(full, []byte(content), filePerm))
}
