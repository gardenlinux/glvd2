package git

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// Committer is an optional git identity.
type Committer struct {
	Name  string
	Email string
}

func (c Committer) isSet() bool { return c.Name != "" && c.Email != "" }

// Writer provides write access to a git repository.
type Writer struct {
	dir       string
	committer Committer
}

// NewWriter creates a [Writer] that executes git commands against the given directory.
func NewWriter(dir string, committer Committer) *Writer {
	return &Writer{dir: dir, committer: committer}
}

// CurrentBranch returns the short name of the currently checked-out branch.
// If HEAD is detached, it returns ErrDetachedHEAD.
func (w *Writer) CurrentBranch(ctx context.Context) (string, error) {
	out, err := RunOutput(ctx, w.dir, "symbolic-ref", "--quiet", "--short", "HEAD")
	if err != nil {
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok && exitErr.ExitCode() == 1 {
			return "", fmt.Errorf("determining current branch: %w", ErrDetachedHEAD)
		}
		return "", fmt.Errorf("determining current branch: %w", err)
	}

	return strings.TrimSpace(out), nil
}

// RevParseHEAD returns the full SHA of the current HEAD commit.
func (w *Writer) RevParseHEAD(ctx context.Context) (string, error) {
	out, err := RunOutput(ctx, w.dir, "rev-parse", "HEAD")
	if err != nil {
		return "", fmt.Errorf("resolving HEAD: %w", err)
	}

	return strings.TrimSpace(out), nil
}

// IsIndexClean reports whether the staging area (index) has no staged changes.
func (w *Writer) IsIndexClean(ctx context.Context) (bool, error) {
	return w.diffCachedQuietArgs(ctx, "checking for a clean index", []string{})
}

// AddPaths stages additions, modifications, and deletions within the given paths.
// It rejects an empty path list and validates each path argument.
func (w *Writer) AddPaths(ctx context.Context, paths ...string) error {
	if len(paths) == 0 {
		return errors.New("AddPaths: at least one path is required")
	}
	for _, p := range paths {
		if err := validatePathArg(p); err != nil {
			return fmt.Errorf("AddPaths: %w", err)
		}
	}

	args := append([]string{"add", "--"}, paths...)
	if err := Run(ctx, w.dir, args...); err != nil {
		return fmt.Errorf("staging paths: %w", err)
	}

	return nil
}

// HasStagedChanges reports whether anything is staged for the given paths.
// It returns an error if no paths are given or any path is invalid.
func (w *Writer) HasStagedChanges(ctx context.Context, paths ...string) (bool, error) {
	if len(paths) == 0 {
		return false, errors.New("HasStagedChanges: at least one path is required")
	}
	for _, p := range paths {
		if err := validatePathArg(p); err != nil {
			return false, fmt.Errorf("HasStagedChanges: %w", err)
		}
	}

	optArgs := append([]string{"--"}, paths...)
	isClean, err := w.diffCachedQuietArgs(ctx, "checking staged paths", optArgs)
	if err != nil {
		return false, err
	}

	return !isClean, nil
}

// Commit creates a partial commit restricted to the given paths.
// The configured committer identity is used when both name and email are set.
func (w *Writer) Commit(ctx context.Context, message string, paths ...string) error {
	if len(paths) == 0 {
		return errors.New("Commit: at least one path is required")
	}
	for _, p := range paths {
		if err := validatePathArg(p); err != nil {
			return fmt.Errorf("Commit: %w", err)
		}
	}

	args := make([]string, 0, len(paths))
	if w.committer.isSet() {
		args = append(args,
			"-c", "user.name="+w.committer.Name,
			"-c", "user.email="+w.committer.Email,
		)
	}
	args = append(args, "commit", "-m", message, "--")
	args = append(args, paths...)

	if err := Run(ctx, w.dir, args...); err != nil {
		return fmt.Errorf("committing paths: %w", err)
	}

	return nil
}

// ChangesInPaths returns a git-status porcelain line for each file under the given
// paths that differs from HEAD (staged, modified, or untracked). A single path
// may yield multiple lines (one per changed file) or none if nothing is dirty.
func (w *Writer) ChangesInPaths(ctx context.Context, paths ...string) ([]string, error) {
	if len(paths) == 0 {
		return nil, errors.New("ChangesInPaths: at least one path is required")
	}
	for _, p := range paths {
		if err := validatePathArg(p); err != nil {
			return nil, fmt.Errorf("ChangesInPaths: %w", err)
		}
	}

	args := append([]string{"status", "--porcelain", "--"}, paths...)
	out, err := RunOutput(ctx, w.dir, args...)
	if err != nil {
		return nil, fmt.Errorf("checking changed paths: %w", err)
	}

	return splitLines(out), nil
}

// RestorePaths restores the given paths to HEAD: restores tracked files and removes
// untracked orphans. Paths not yet tracked at HEAD are skipped.
func (w *Writer) RestorePaths(ctx context.Context, paths ...string) error {
	if len(paths) == 0 {
		return errors.New("RestorePaths: at least one path is required")
	}
	for _, p := range paths {
		if err := validatePathArg(p); err != nil {
			return fmt.Errorf("RestorePaths: %w", err)
		}
	}

	// Restore only paths tracked at HEAD. `git restore` aborts for all pathspecs
	// if any one is unmatched, so probe first and pass just the tracked subset.
	tracked, err := w.getTrackedAtHEAD(ctx, paths...)
	if err != nil {
		return fmt.Errorf("probing tracked paths: %w", err)
	}
	if len(tracked) > 0 {
		restoreArgs := append([]string{"restore", "--source=HEAD", "--staged", "--worktree", "--"}, tracked...)
		if rErr := Run(ctx, w.dir, restoreArgs...); rErr != nil {
			return fmt.Errorf("restoring paths to HEAD: %w", rErr)
		}
	}

	// Remove untracked orphans; -x omitted to preserve gitignored files.
	cleanArgs := append([]string{"clean", "-fd", "--"}, paths...)
	if cErr := Run(ctx, w.dir, cleanArgs...); cErr != nil {
		return fmt.Errorf("cleaning untracked paths: %w", cErr)
	}

	return nil
}

// getTrackedAtHEAD returns the subset of paths that have tracked content at HEAD.
// It uses `git ls-tree`, which exits 0 and prints nothing for unmatched paths.
func (w *Writer) getTrackedAtHEAD(ctx context.Context, paths ...string) ([]string, error) {
	tracked := make([]string, 0, len(paths))
	for _, p := range paths {
		out, err := RunOutput(ctx, w.dir, "ls-tree", "--name-only", "HEAD", "--", p)
		if err != nil {
			return nil, fmt.Errorf("checking whether %q is tracked at HEAD: %w", p, err)
		}
		if strings.TrimSpace(out) != "" { // empty for untracked paths
			tracked = append(tracked, p)
		}
	}

	return tracked, nil
}

// ResetSoft moves HEAD back to given sha, keeping the working tree and staged entries.
func (w *Writer) ResetSoft(ctx context.Context, sha string) error {
	if err := validateCommitSHA(sha); err != nil {
		return fmt.Errorf("ResetSoft: %w", err)
	}

	if err := Run(ctx, w.dir, "reset", "--soft", sha); err != nil {
		return fmt.Errorf("soft-resetting to %s: %w", sha, err)
	}

	return nil
}

// PushFastForward pushes the named local branch ref to the same ref on remote, fast-forward only.
// On a non-fast-forward rejection it returns ErrNonFastForward; other failures are returned directly.
func (w *Writer) PushFastForward(ctx context.Context, remote, branch string) error {
	if err := validateRefArg(remote); err != nil {
		return fmt.Errorf("PushFastForward: invalid remote: %w", err)
	}
	if err := validateRefArg(branch); err != nil {
		return fmt.Errorf("PushFastForward: invalid branch: %w", err)
	}

	err := Run(ctx, w.dir, "push", remote, "refs/heads/"+branch+":refs/heads/"+branch)
	if err == nil {
		return nil
	}

	if errors.Is(err, ErrNonFastForward) {
		return fmt.Errorf("pushing to %s/%s: %w", remote, branch, ErrNonFastForward)
	}

	return fmt.Errorf("pushing to %s/%s: %w", remote, branch, err)
}

// diffCachedQuiet runs `git diff --cached --quiet` and checks it return codes.
// optArgs allows to extend the command.
// No changes: true. Changes present: false.
// Any other exit code is an error.
func (w *Writer) diffCachedQuietArgs(ctx context.Context, action string, optArgs []string) (bool, error) {
	args := append([]string{"diff", "--cached", "--quiet"}, optArgs...)
	err := Run(ctx, w.dir, args...)
	if err == nil {
		return true, nil
	}

	if exitErr, ok := errors.AsType[*exec.ExitError](err); ok && exitErr.ExitCode() == 1 {
		// Exit code 1 means there are staged changes.
		return false, nil
	}

	return false, fmt.Errorf("%s: %w", action, err)
}

// validateRefArg validates a remote or branch name argument for git:
//   - must not be empty
//   - must not start with '-' (would be interpreted as a flag)
//   - must not contain whitespace, newlines, or NUL bytes
func validateRefArg(ref string) error {
	if ref == "" {
		return errors.New("ref argument must not be empty")
	}
	if strings.HasPrefix(ref, "-") {
		return fmt.Errorf("ref argument %q must not start with '-'", ref)
	}
	if strings.ContainsAny(ref, " \t\n\r\x00") {
		return fmt.Errorf("ref argument %q must not contain whitespace or control characters", ref)
	}

	return nil
}
