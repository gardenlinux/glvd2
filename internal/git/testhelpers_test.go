package git_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// gitEnv returns the minimal environment needed for isolated git operations.
// It suppresses global and system config so developer/CI settings like gpg signing,
// commit templates, or hooks cannot interfere with tests.
func gitEnv() []string {
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

// runGit executes a git command in dir with the isolated environment.
// It uses t.Context() for cancellation and fails the test immediately on any error.
func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()

	cmd := exec.CommandContext(t.Context(), "git", args...) //nolint:gosec // test helper only constructs internal args
	cmd.Dir = dir
	cmd.Env = gitEnv()

	out, err := cmd.Output()
	require.NoError(t, err, "git %s", strings.Join(args, " "))

	return string(out)
}

// initTestRepo creates a new, isolated git repository in a temp directory and returns its path.
func initTestRepo(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()

	runGit(t, dir, "init")
	runGit(t, dir, "config", "user.name", "Test")
	runGit(t, dir, "config", "user.email", "test@example.com")
	runGit(t, dir, "config", "commit.gpgsign", "false")

	return dir
}

// headSHA returns the full SHA of the current HEAD commit.
func headSHA(t *testing.T, dir string) string {
	t.Helper()

	return strings.TrimSpace(runGit(t, dir, "rev-parse", "HEAD"))
}

// addEmptyCommit creates an empty commit with the given message and returns the
// full commit SHA. Multiline messages (e.g. with trailers) should be passed as a
// single string; no shell is involved so newlines are preserved correctly.
func addEmptyCommit(t *testing.T, dir, message string) string {
	t.Helper()

	runGit(t, dir, "commit", "--allow-empty", "-m", message)

	return headSHA(t, dir)
}

// stageAllAndCommit stages all changes (including deletions) and commits with the given message.
// Returns the full commit SHA.
func stageAllAndCommit(t *testing.T, dir, message string) string {
	t.Helper()

	runGit(t, dir, "add", "-A")
	runGit(t, dir, "commit", "-m", message)

	return headSHA(t, dir)
}

// writeFile creates (or overwrites) a file relative to dir, creating any required
// parent directories automatically.
func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()

	full := filepath.Join(dir, rel)
	require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
	require.NoError(t, os.WriteFile(full, []byte(content), 0o644))
}
