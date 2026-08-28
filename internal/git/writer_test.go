package git_test

import (
	"strings"
	"testing"

	"github.com/gardenlinux/glvd2/internal/git"
	"github.com/gardenlinux/glvd2/internal/gittest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWriterCurrentBranch verifies branch name resolution and detached-HEAD detection.
func TestWriterCurrentBranch(t *testing.T) {
	t.Parallel()

	t.Run("returns branch name on named branch", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		gittest.AddEmptyCommit(t, dir, "chore: init")

		s := git.NewWriter(dir, git.Committer{})
		branch, err := s.CurrentBranch(t.Context())
		require.NoError(t, err)
		assert.Equal(t, "main", branch)
	})

	t.Run("returns non-default branch name", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		gittest.AddEmptyCommit(t, dir, "chore: init")
		gittest.Run(t, dir, "checkout", "-b", "feature-x")

		s := git.NewWriter(dir, git.Committer{})
		branch, err := s.CurrentBranch(t.Context())
		require.NoError(t, err)
		assert.Equal(t, "feature-x", branch)
	})

	t.Run("returns ErrDetachedHEAD in detached state", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		sha := gittest.AddEmptyCommit(t, dir, "chore: init")
		// Detach HEAD by checking out the commit SHA directly.
		gittest.Run(t, dir, "checkout", "--detach", sha)

		s := git.NewWriter(dir, git.Committer{})
		_, err := s.CurrentBranch(t.Context())
		require.Error(t, err)
		assert.ErrorIs(t, err, git.ErrDetachedHEAD)
	})
}

// TestWriterRevParseHEAD verifies HEAD resolution.
func TestWriterRevParseHEAD(t *testing.T) {
	t.Parallel()

	dir := gittest.InitRepo(t)
	want := gittest.AddEmptyCommit(t, dir, "chore: init")

	s := git.NewWriter(dir, git.Committer{})
	got, err := s.RevParseHEAD(t.Context())
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

// TestWriterIsIndexClean verifies clean/dirty detection without erroring on a
// merely-dirty index.
func TestWriterIsIndexClean(t *testing.T) {
	t.Parallel()

	t.Run("clean index returns true", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		gittest.AddEmptyCommit(t, dir, "chore: init")

		s := git.NewWriter(dir, git.Committer{})
		isClean, err := s.IsIndexClean(t.Context())
		require.NoError(t, err)
		assert.True(t, isClean)
	})

	t.Run("staged change returns false without error", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		gittest.AddEmptyCommit(t, dir, "chore: init")
		gittest.WriteFile(t, dir, "foo/a.txt", "hello")
		gittest.Run(t, dir, "add", "foo/a.txt")

		s := git.NewWriter(dir, git.Committer{})
		clean, err := s.IsIndexClean(t.Context())
		require.NoError(t, err)
		assert.False(t, clean)
	})

	t.Run("unstaged working-tree change keeps index clean", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		gittest.WriteFile(t, dir, "foo/a.txt", "hello")
		gittest.StageAllAndCommit(t, dir, "chore: init")
		// Modify a tracked file on disk without staging it.
		gittest.WriteFile(t, dir, "foo/a.txt", "modified")

		s := git.NewWriter(dir, git.Committer{})
		clean, err := s.IsIndexClean(t.Context())
		require.NoError(t, err)
		// The index has nothing staged even though the working tree is dirty.
		assert.True(t, clean)
	})
}

// TestWriterAddPathsValidation needs paths.
func TestWriterAddPathsValidation(t *testing.T) {
	t.Parallel()

	dir := gittest.InitRepo(t)
	s := git.NewWriter(dir, git.Committer{})

	err := s.AddPaths(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AddPaths")
}

// TestWriterHasStagedChanges verifies scoped staging detection.
func TestWriterHasStagedChanges(t *testing.T) {
	t.Parallel()

	t.Run("nothing staged returns false", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		gittest.WriteFile(t, dir, "foo/a.txt", "hello")
		gittest.StageAllAndCommit(t, dir, "chore: init")

		s := git.NewWriter(dir, git.Committer{})
		require.NoError(t, s.AddPaths(t.Context(), "foo"))

		staged, err := s.HasStagedChanges(t.Context(), "foo")
		require.NoError(t, err)
		assert.False(t, staged)
	})

	t.Run("staged content returns true", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		gittest.AddEmptyCommit(t, dir, "chore: init")
		gittest.WriteFile(t, dir, "foo/a.txt", "hello")

		s := git.NewWriter(dir, git.Committer{})
		require.NoError(t, s.AddPaths(t.Context(), "foo"))

		staged, err := s.HasStagedChanges(t.Context(), "foo")
		require.NoError(t, err)
		assert.True(t, staged)
	})

	t.Run("unstaged working-tree change is not reported as staged", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		gittest.WriteFile(t, dir, "foo/a.txt", "hello")
		gittest.StageAllAndCommit(t, dir, "chore: init")
		// Modify a tracked file on disk without staging it.
		gittest.WriteFile(t, dir, "foo/a.txt", "modified")

		s := git.NewWriter(dir, git.Committer{})
		staged, err := s.HasStagedChanges(t.Context(), "foo")
		require.NoError(t, err)
		// Nothing is staged: only the working tree differs.
		assert.False(t, staged)
	})
}

// TestWriterCommitPartial verifies path-scoped commits include owned
// new/modified/deleted files, exclude pre-staged unrelated content, and
// preserve other staged entries.
func TestWriterCommitPartial(t *testing.T) {
	t.Parallel()

	dir := gittest.InitRepo(t)
	// Baseline commit containing files we will later modify/delete.
	gittest.WriteFile(t, dir, "foo/keep.txt", "keep")
	gittest.WriteFile(t, dir, "foo/del.txt", "delete me")
	gittest.StageAllAndCommit(t, dir, "chore: init")

	// Owned changes: new + modified + deleted, all under foo/.
	gittest.WriteFile(t, dir, "foo/new.txt", "new")
	gittest.WriteFile(t, dir, "foo/keep.txt", "modified")
	gittest.Run(t, dir, "rm", "foo/del.txt")

	// Pre-staged unrelated content outside the owned path.
	gittest.WriteFile(t, dir, "bar/unrelated.txt", "unrelated")
	gittest.Run(t, dir, "add", "bar/unrelated.txt")

	s := git.NewWriter(dir, git.Committer{})
	require.NoError(t, s.AddPaths(t.Context(), "foo"))
	require.NoError(t, s.Commit(t.Context(), "chore(foo): update", "foo"))

	// The commit should touch only foo/ files.
	changed := gittest.Run(t, dir, "show", "--name-only", "--format=", "HEAD")
	assert.Contains(t, changed, "foo/new.txt")
	assert.Contains(t, changed, "foo/keep.txt")
	assert.Contains(t, changed, "foo/del.txt")
	assert.NotContains(t, changed, "bar/unrelated.txt")

	// The unrelated pre-staged entry must remain staged (uncommitted).
	stagedFiles := gittest.Run(t, dir, "diff", "--cached", "--name-only")
	assert.Contains(t, stagedFiles, "bar/unrelated.txt")
}

// TestWriterCommitIdentity verifies -c committer identity injection.
func TestWriterCommitIdentity(t *testing.T) {
	t.Parallel()

	t.Run("configured identity is used", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		gittest.AddEmptyCommit(t, dir, "chore: init")
		gittest.WriteFile(t, dir, "foo/a.txt", "hello")

		s := git.NewWriter(dir, git.Committer{Name: "Bot Name", Email: "bot@example.com"})
		require.NoError(t, s.AddPaths(t.Context(), "foo"))
		require.NoError(t, s.Commit(t.Context(), "chore(foo): add", "foo"))

		out := strings.TrimSpace(gittest.Run(t, dir, "log", "-1", "--format=%cn/%ce"))
		assert.Equal(t, "Bot Name/bot@example.com", out)
	})

	t.Run("ambient identity used when not configured", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		gittest.AddEmptyCommit(t, dir, "chore: init")
		gittest.WriteFile(t, dir, "foo/a.txt", "hello")

		s := git.NewWriter(dir, git.Committer{})
		require.NoError(t, s.AddPaths(t.Context(), "foo"))
		require.NoError(t, s.Commit(t.Context(), "chore(foo): add", "foo"))

		out := strings.TrimSpace(gittest.Run(t, dir, "log", "-1", "--format=%cn/%ce"))
		assert.Equal(t, "Test/test@example.com", out)
	})
}

// TestWriterResetSoft verifies HEAD moves back and pre-existing staged entries are preserved.
func TestWriterResetSoft(t *testing.T) {
	t.Parallel()

	dir := gittest.InitRepo(t)
	start := gittest.AddEmptyCommit(t, dir, "chore: init")

	// Pre-existing staged entry that must survive the soft reset.
	gittest.WriteFile(t, dir, "bar/pre.txt", "prestaged")
	gittest.Run(t, dir, "add", "bar/pre.txt")

	// Make a commit we intend to undo.
	gittest.WriteFile(t, dir, "foo/a.txt", "hello")
	s := git.NewWriter(dir, git.Committer{})
	require.NoError(t, s.AddPaths(t.Context(), "foo"))
	require.NoError(t, s.Commit(t.Context(), "chore(foo): add", "foo"))

	require.NoError(t, s.ResetSoft(t.Context(), start))

	assert.Equal(t, start, gittest.HeadSHA(t, dir))

	stagedFiles := gittest.Run(t, dir, "diff", "--cached", "--name-only")
	assert.Contains(t, stagedFiles, "bar/pre.txt")
}

// TestWriterPushFastForward verifies FF push succeeds and a non-FF push returns ErrNonFastForward.
func TestWriterPushFastForward(t *testing.T) {
	t.Parallel()

	t.Run("fast-forward push succeeds and updates remote branch ref", func(t *testing.T) {
		t.Parallel()

		remote := gittest.InitBareRemote(t)
		dir := gittest.InitRepo(t)
		gittest.Run(t, dir, "remote", "add", "origin", remote)
		sha := gittest.AddEmptyCommit(t, dir, "chore: init")

		s := git.NewWriter(dir, git.Committer{})
		require.NoError(t, s.PushFastForward(t.Context(), "origin", "main"))

		// Verify the remote branch ref (refs/heads/main) points at our commit.
		remoteSHA := strings.TrimSpace(gittest.Run(t, remote, "rev-parse", "refs/heads/main"))
		assert.Equal(t, sha, remoteSHA)
	})

	t.Run("non-fast-forward push returns ErrNonFastForward", func(t *testing.T) {
		t.Parallel()

		remote := gittest.InitBareRemote(t)

		// First clone advances the remote branch.
		other := t.TempDir()
		gittest.Run(t, other, "clone", remote, ".")
		gittest.Run(t, other, "config", "user.name", "Test")
		gittest.Run(t, other, "config", "user.email", "test@example.com")
		gittest.AddEmptyCommit(t, other, "chore: first")
		gittest.Run(t, other, "push", "origin", "HEAD:refs/heads/main")

		// Our repo starts from the same point but diverges.
		dir := t.TempDir()
		gittest.Run(t, dir, "clone", remote, ".")
		gittest.Run(t, dir, "config", "user.name", "Test")
		gittest.Run(t, dir, "config", "user.email", "test@example.com")
		gittest.AddEmptyCommit(t, dir, "chore: init")

		// Remote advances again after we captured our base.
		gittest.AddEmptyCommit(t, other, "chore: second")
		gittest.Run(t, other, "push", "origin", "HEAD:refs/heads/main")

		s := git.NewWriter(dir, git.Committer{})
		err := s.PushFastForward(t.Context(), "origin", "main")
		require.Error(t, err)
		assert.ErrorIs(t, err, git.ErrNonFastForward)
	})
}

// TestWriterPushFastForwardValidation verifies remote/branch validation.
func TestWriterPushFastForwardValidation(t *testing.T) {
	t.Parallel()

	dir := gittest.InitRepo(t)
	s := git.NewWriter(dir, git.Committer{})
	require.Error(t, s.PushFastForward(t.Context(), "origin", ""))
	require.Error(t, s.PushFastForward(t.Context(), "origin", "-branch"))
}

// TestWriterChangesInPaths verifies that ChangesInPaths correctly reports clean and dirty states.
func TestWriterChangesInPaths(t *testing.T) {
	t.Parallel()

	t.Run("clean paths return empty", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		gittest.WriteFile(t, dir, "owned/a.txt", "hello")
		gittest.StageAllAndCommit(t, dir, "chore: init")

		s := git.NewWriter(dir, git.Committer{})
		changed, err := s.ChangesInPaths(t.Context(), "owned")
		require.NoError(t, err)
		assert.Empty(t, changed)
	})

	t.Run("modified tracked file is reported", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		gittest.WriteFile(t, dir, "owned/a.txt", "hello")
		gittest.StageAllAndCommit(t, dir, "chore: init")
		gittest.WriteFile(t, dir, "owned/a.txt", "modified")

		s := git.NewWriter(dir, git.Committer{})
		changed, err := s.ChangesInPaths(t.Context(), "owned")
		require.NoError(t, err)
		assert.NotEmpty(t, changed)
	})

	t.Run("staged file is reported", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		gittest.AddEmptyCommit(t, dir, "chore: init")
		gittest.WriteFile(t, dir, "owned/b.txt", "new")
		gittest.Run(t, dir, "add", "owned/b.txt")

		s := git.NewWriter(dir, git.Committer{})
		changed, err := s.ChangesInPaths(t.Context(), "owned")
		require.NoError(t, err)
		assert.NotEmpty(t, changed)
	})

	t.Run("untracked file is reported", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		gittest.AddEmptyCommit(t, dir, "chore: init")
		gittest.WriteFile(t, dir, "owned/c.txt", "untracked")

		s := git.NewWriter(dir, git.Committer{})
		changed, err := s.ChangesInPaths(t.Context(), "owned")
		require.NoError(t, err)
		assert.NotEmpty(t, changed)
	})

	t.Run("out-of-scope changes are not reported", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		gittest.WriteFile(t, dir, "owned/a.txt", "hello")
		gittest.StageAllAndCommit(t, dir, "chore: init")
		// Dirty a path outside the owned directory.
		gittest.WriteFile(t, dir, "other/x.txt", "unrelated")

		s := git.NewWriter(dir, git.Committer{})
		changed, err := s.ChangesInPaths(t.Context(), "owned")
		require.NoError(t, err)
		assert.Empty(t, changed)
	})
}

// TestWriterRestorePaths verifies that RestorePaths restores the owned directory
// to HEAD, removes untracked orphans, and leaves out-of-scope staged changes intact.
func TestWriterRestorePaths(t *testing.T) {
	t.Parallel()

	t.Run("restores modified file and removes untracked orphan", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		gittest.WriteFile(t, dir, "owned/a.txt", "original")
		gittest.StageAllAndCommit(t, dir, "chore: init")

		// Dirty the owned directory: modify a tracked file and add an untracked one.
		gittest.WriteFile(t, dir, "owned/a.txt", "modified")
		gittest.WriteFile(t, dir, "owned/orphan.txt", "should be removed")

		// Stage an unrelated change outside the owned path.
		gittest.WriteFile(t, dir, "other/x.txt", "unrelated")
		gittest.Run(t, dir, "add", "other/x.txt")

		s := git.NewWriter(dir, git.Committer{})
		require.NoError(t, s.RestorePaths(t.Context(), "owned"))

		// owned/a.txt should be back to original content.
		changed := strings.TrimSpace(gittest.Run(t, dir, "status", "--porcelain", "--", "owned"))
		assert.Empty(t, changed, "owned directory should be clean after restore")

		// The out-of-scope staged entry must still be staged.
		stagedFiles := gittest.Run(t, dir, "diff", "--cached", "--name-only")
		assert.Contains(t, stagedFiles, "other/x.txt")
	})

	t.Run("restores tracked path even when another path is untracked", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		gittest.WriteFile(t, dir, "tracked/a.txt", "original")
		gittest.StageAllAndCommit(t, dir, "chore: init")

		// Dirty the tracked path and create a first-time untracked path.
		gittest.WriteFile(t, dir, "tracked/a.txt", "modified")
		gittest.WriteFile(t, dir, "untracked/new.txt", "first-ever content")

		s := git.NewWriter(dir, git.Committer{})
		// A single unmatched pathspec must not abort restore for the tracked one.
		require.NoError(t, s.RestorePaths(t.Context(), "tracked", "untracked"))

		// tracked/a.txt must be reset to HEAD content, and the path clean.
		content := gittest.Run(t, dir, "show", "HEAD:tracked/a.txt")
		assert.Equal(t, "original", content)

		// Both the tracked path and the untracked orphan must be clean now.
		changed := strings.TrimSpace(gittest.Run(t, dir, "status", "--porcelain", "--", "tracked", "untracked"))
		assert.Empty(t, changed)
	})

	t.Run("succeeds when no files are tracked at HEAD (first-ever run)", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		gittest.AddEmptyCommit(t, dir, "chore: init")

		// owned/ has never been committed; RestorePaths must not fail.
		gittest.WriteFile(t, dir, "owned/new.txt", "new file")

		s := git.NewWriter(dir, git.Committer{})
		require.NoError(t, s.RestorePaths(t.Context(), "owned"))

		// The untracked file should have been cleaned away.
		changed := strings.TrimSpace(gittest.Run(t, dir, "status", "--porcelain", "--", "owned"))
		assert.Empty(t, changed)
	})
}
