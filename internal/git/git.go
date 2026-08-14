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

// Error is returned by git commands when they exit non-zero.
// It carries the original stderr output separately so callers can inspect it
// without parsing a formatted error string.
type Error struct {
	Args   []string
	Stderr string
	Err    error
}

func (e *Error) Error() string {
	return fmt.Sprintf("git %s: %s (stderr: %s)",
		strings.Join(e.Args, " "), e.Err, strings.TrimSpace(e.Stderr))
}

func (e *Error) Unwrap() error { return e.Err }

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
		return &Error{Args: args, Stderr: stderr.String(), Err: err}
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
		return "", &Error{Args: args, Stderr: stderr.String(), Err: err}
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
		var gitErr *Error
		if errors.As(err, &gitErr) && strings.Contains(gitErr.Stderr, "does not have any commits yet") {
			return "", nil
		}
		// A non-zero exit indicates a real error (not a repo, bad ref, etc).
		return "", err
	}

	return strings.TrimSpace(stdout), nil
}

// DiffFilesSince returns the list of file paths changed between commitSHA and HEAD
// within the given path prefix. Returns nil if no files were modified.
func DiffFilesSince(ctx context.Context, dir, commitSHA, pathPrefix string) ([]string, error) {
	if err := validateCommitSHA(commitSHA); err != nil {
		return nil, fmt.Errorf("DiffFilesSince: %w", err)
	}

	if err := validatePathArg(pathPrefix); err != nil {
		return nil, fmt.Errorf("DiffFilesSince: %w", err)
	}

	stdout, err := RunOutput(ctx, dir,
		"diff", "--name-only", commitSHA, "HEAD", "--", pathPrefix+"/",
	)
	if err != nil {
		return nil, fmt.Errorf("listing files changed since %s: %w", commitSHA, err)
	}

	trimmed := strings.TrimSpace(stdout)
	if trimmed == "" {
		return nil, nil
	}

	return strings.Split(trimmed, "\n"), nil
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
