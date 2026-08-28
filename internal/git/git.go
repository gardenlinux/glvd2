package git

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// ErrNoCommitsYet is used when a git command fails because the repository
// has no commits yet like on a freshly initialized repo.
var ErrNoCommitsYet = errors.New("repository has no commits yet")

// ErrNonFastForward is returned when the remote rejected the push,
// because it would not be a fast-forward merge.
var ErrNonFastForward = errors.New("push rejected: non-fast-forward")

// ErrDetachedHEAD is returned when HEAD is not on any branch.
var ErrDetachedHEAD = errors.New("HEAD is detached: not on any branch")

// newError builds an error describing a failed git command and returns custom
// ones for known stderr matches.
func newError(args []string, stderr string, err error) error {
	base := fmt.Errorf("git %s: %w (stderr: %s)",
		strings.Join(args, " "), err, strings.TrimSpace(stderr))
	if kind := classifyStderr(stderr); kind != nil {
		return fmt.Errorf("%w: %w", base, kind)
	}

	return base
}

// classifyStderr maps git's stderr output to a known sentinel error, or nil if none matches.
func classifyStderr(stderr string) error {
	lower := strings.ToLower(stderr)

	switch {
	case strings.Contains(lower, "does not have any commits yet"):
		return ErrNoCommitsYet
	// These are the substrings git prints when it rejects a non-fast-forward push.
	case strings.Contains(lower, "non-fast-forward"),
		strings.Contains(lower, "rejected"),
		strings.Contains(lower, "fetch first"):
		return ErrNonFastForward
	default:
		return nil
	}
}

// commitSHAPattern matches valid git commit SHAs: lowercase hex, 4-40 characters.
// 4 characters is the minimum that git accepts for an abbreviated SHA.
var commitSHAPattern = regexp.MustCompile(`^[0-9a-f]{4,40}$`)

// anchorPattern matches trailer-safe anchors (used with grep).
var anchorPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _:-]*$`)

// validateCommitSHA returns an error if sha is not a valid git commit SHA.
func validateCommitSHA(sha string) error {
	if !commitSHAPattern.MatchString(sha) {
		return fmt.Errorf("invalid commit SHA %q: must be 4-40 lowercase hex characters", sha)
	}

	return nil
}

// validatePathArg returns an error if p is not a safe path argument for git:
//   - must not be empty
//   - must not start with '-' (would be interpreted as a flag)
//   - must not contain '..' components (path traversal)
func validatePathArg(p string) error {
	if p == "" {
		return errors.New("path argument must not be empty")
	}
	if strings.HasPrefix(p, "-") {
		return fmt.Errorf("path argument %q must not start with '-'", p)
	}
	if slices.Contains(strings.Split(filepath.ToSlash(p), "/"), "..") {
		return fmt.Errorf("path argument %q must not contain '..' components", p)
	}

	return nil
}

// validateTrailer rejects strings that are not valid git message trailers.
func validateTrailer(anchor string) error {
	if !anchorPattern.MatchString(anchor) {
		return fmt.Errorf("invalid anchor %q: must start with a letter or digit and "+
			"contain only letters, digits, spaces, '-', '_', or ':'", anchor)
	}

	return nil
}

// Run executes a git command in the given directory, returning an error with stderr on failure.
func Run(ctx context.Context, dir string, args ...string) error {
	cmd := exec.CommandContext(ctx, "git", args...) //nolint:gosec // args are only constructed internally
	cmd.Dir = dir

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return newError(args, stderr.String(), err)
	}

	return nil
}

// RunOutput executes a git command in the given directory and returns stdout.
func RunOutput(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...) //nolint:gosec // args are only constructed internally
	cmd.Dir = dir

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", newError(args, stderr.String(), err)
	}

	return stdout.String(), nil
}

// FindCommitByMessageAnchor returns the SHA of the most recent commit whose message
// contains a line exactly matching anchor (git message trailer).
func FindCommitByMessageAnchor(ctx context.Context, dir, anchor string) (string, error) {
	if err := validateTrailer(anchor); err != nil {
		return "", fmt.Errorf("FindCommitByMessageAnchor: %w", err)
	}

	stdout, err := RunOutput(ctx, dir,
		"log", "-1", "--grep=^"+anchor+"$", "--format=%H",
	)
	if err != nil {
		// git log exits non-zero on a repo with no commits yet; treat as "no match".
		if errors.Is(err, ErrNoCommitsYet) {
			return "", nil
		}
		// A non-zero exit indicates a real error (not a repo, bad ref, etc).
		return "", err
	}

	return strings.TrimSpace(stdout), nil
}

// DiffFilesSince returns file paths that differ from commitSHA within the given path prefix,
// covering tracked changes (committed, staged, or unstaged) and untracked files.
// Returns nil if none differ.
func DiffFilesSince(ctx context.Context, dir, commitSHA, pathPrefix string) ([]string, error) {
	if err := validateCommitSHA(commitSHA); err != nil {
		return nil, fmt.Errorf("DiffFilesSince: %w", err)
	}

	if err := validatePathArg(pathPrefix); err != nil {
		return nil, fmt.Errorf("DiffFilesSince: %w", err)
	}

	// Tracked changes vs the working tree.
	diffOut, err := RunOutput(ctx, dir,
		"diff", "--name-only", commitSHA, "--", pathPrefix+"/",
	)
	if err != nil {
		return nil, fmt.Errorf("listing files changed since %s: %w", commitSHA, err)
	}

	// Untracked files, missed by git diff.
	untrackedOut, err := RunOutput(ctx, dir,
		"ls-files", "--others", "--exclude-standard", "--", pathPrefix+"/",
	)
	if err != nil {
		return nil, fmt.Errorf("listing untracked files under %s: %w", pathPrefix, err)
	}

	files := append(splitLines(diffOut), splitLines(untrackedOut)...)
	if len(files) == 0 {
		return nil, nil
	}

	slices.Sort(files)

	return slices.Compact(files), nil
}

// splitLines trims and splits by newlines into a slice, returning nil for empty input.
func splitLines(out string) []string {
	trimmed := strings.TrimSpace(out)
	if trimmed == "" {
		return nil
	}

	return strings.Split(trimmed, "\n")
}

// ShowFileAtCommit returns the content of a file at a specific commit.
// Returns nil, nil if the file did not exist at the time of that commit.
// Returns an error if the commit SHA is not found or another git error occurs.
func ShowFileAtCommit(ctx context.Context, dir, commitSHA, filePath string) ([]byte, error) {
	if err := validateCommitSHA(commitSHA); err != nil {
		return nil, fmt.Errorf("ShowFileAtCommit: %w", err)
	}

	if err := validatePathArg(filePath); err != nil {
		return nil, fmt.Errorf("ShowFileAtCommit: %w", err)
	}

	// Probe for the path with ls-tree instead of parsing git show's stderr,
	// which is fragile and locale-sensitive.
	// A non-zero exit means a bad commit SHA or other git error.
	out, err := RunOutput(ctx, dir, "ls-tree", "--name-only", commitSHA, "--", filePath)
	if err != nil {
		return nil, fmt.Errorf("checking %s at %s: %w", filePath, commitSHA, err)
	}

	// Empty output means the commit is valid but the path does not exist there.
	if strings.TrimSpace(out) == "" {
		return nil, nil
	}

	// The path exists, so fetch its content.
	content, err := RunOutput(ctx, dir, "show", commitSHA+":"+filePath)
	if err != nil {
		return nil, fmt.Errorf("showing %s at %s: %w", filePath, commitSHA, err)
	}

	return []byte(content), nil
}
