package publish_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gardenlinux/glvd2/internal/git"
	"github.com/gardenlinux/glvd2/internal/gittest"
	"github.com/gardenlinux/glvd2/internal/publish"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These integration tests use the actual git binary with the publish.Service
// and exercise the full commit/push/rollback flow against real repositories,
// so staged vs. unstaged handling and the actual push are verified end-to-end.

// initTestRepo creates an isolated repository with an initial commit on main and
// returns its path.
func initTestRepo(t *testing.T) string {
	t.Helper()

	dir := gittest.InitRepo(t)
	gittest.AddEmptyCommit(t, dir, "chore: init")

	return dir
}

// seedCommitGroupDirs commits a placeholder in each test commit group's path, so they are
// tracked and `git add <dir>` succeeds even when a group has no new content.
func seedCommitGroupDirs(t *testing.T, dir string) {
	t.Helper()

	gittest.WriteFile(t, dir, "data/assessments/.gitkeep", "")
	gittest.WriteFile(t, dir, "data/audit/.gitkeep", "")
	gittest.StageAllAndCommit(t, dir, "chore: seed group dirs")
}

// TestIntegrationCommitCreatesOneCommitPerNonEmptyGroup verifies that each group
// with staged content becomes exactly one commit and empty groups are skipped.
func TestIntegrationCommitCreatesOneCommitPerNonEmptyGroup(t *testing.T) {
	t.Parallel()

	dir := initTestRepo(t)
	seedCommitGroupDirs(t, dir)

	// Only the assessments group has content; audit stays empty.
	gittest.WriteFile(t, dir, "data/assessments/a.json", `{"a":1}`)

	cfg := publish.Config{
		Target: publish.Target{Remote: "origin", Branch: "main"},
		Level:  publish.LevelCommit,
	}
	s := publish.NewService(cfg, git.NewWriter(dir, git.Committer{}))

	require.NoError(t, s.Run(t.Context(), createCommitGroup(), testMessageForCommitGroup))

	// Exactly one new commit on top of the seeded history.
	subjects := gittest.GetCommitSubjects(t, dir)
	require.Equal(t, []string{
		"data(assessments): update",
		"chore: seed group dirs",
		"chore: init",
	}, subjects)

	// The commit contains only the assessments file.
	changed := gittest.Run(t, dir, "show", "--name-only", "--format=", "HEAD")
	assert.Contains(t, changed, "data/assessments/a.json")
	assert.NotContains(t, changed, "data/audit")
}

// TestIntegrationCommitExcludesForeignStagedContent verifies that foreign content
// already staged in the index is not swept into a group's path-scoped commit and
// remains staged afterwards.
func TestIntegrationCommitExcludesForeignStagedContent(t *testing.T) {
	t.Parallel()

	dir := initTestRepo(t)
	seedCommitGroupDirs(t, dir)

	gittest.WriteFile(t, dir, "data/assessments/a.json", `{"a":1}`)
	// Foreign content staged in the index before the run; it must survive untouched.
	gittest.WriteFile(t, dir, "data/other/foreign.txt", "leave me")
	gittest.Run(t, dir, "add", "data/other/foreign.txt")

	cfg := publish.Config{
		Target: publish.Target{Remote: "origin", Branch: "main"},
		Level:  publish.LevelCommit,
	}
	s := publish.NewService(cfg, git.NewWriter(dir, git.Committer{}))

	require.NoError(t, s.Run(t.Context(), createCommitGroup(), testMessageForCommitGroup))

	// The commit contains only the assessments file, not the foreign staged file.
	changed := gittest.Run(t, dir, "show", "--name-only", "--format=", "HEAD")
	assert.Contains(t, changed, "data/assessments/a.json")
	assert.NotContains(t, changed, "data/other/foreign.txt")

	// The foreign file is still staged (present in the index) but uncommitted.
	staged := gittest.Run(t, dir, "diff", "--cached", "--name-only")
	assert.Contains(t, staged, "data/other/foreign.txt")
}

// TestIntegrationCommitTwoNonEmptyGroupsAreIsolated verifies that two populated groups
// produce two separate commits and that each commit contains only its own group's files.
func TestIntegrationCommitTwoNonEmptyGroupsAreIsolated(t *testing.T) {
	t.Parallel()

	dir := initTestRepo(t)
	seedCommitGroupDirs(t, dir)

	gittest.WriteFile(t, dir, "data/assessments/a.json", `{"a":1}`)
	gittest.WriteFile(t, dir, "data/audit/b.json", `{"b":2}`)

	cfg := publish.Config{
		Target: publish.Target{Remote: "origin", Branch: "main"},
		Level:  publish.LevelCommit,
	}
	s := publish.NewService(cfg, git.NewWriter(dir, git.Committer{}))

	require.NoError(t, s.Run(t.Context(), createCommitGroup(), testMessageForCommitGroup))

	// One commit per group, in group order (newest first in the log).
	subjects := gittest.GetCommitSubjects(t, dir)
	require.Equal(t, []string{
		"data(audit): update",
		"data(assessments): update",
		"chore: seed group dirs",
		"chore: init",
	}, subjects)

	// HEAD is the audit commit: contains only the audit file.
	auditChanged := gittest.Run(t, dir, "show", "--name-only", "--format=", "HEAD")
	assert.Contains(t, auditChanged, "data/audit/b.json")
	assert.NotContains(t, auditChanged, "data/assessments/a.json")

	// HEAD~1 is the assessments commit: contains only the assessments file.
	assessmentsChanged := gittest.Run(t, dir, "show", "--name-only", "--format=", "HEAD~1")
	assert.Contains(t, assessmentsChanged, "data/assessments/a.json")
	assert.NotContains(t, assessmentsChanged, "data/audit/b.json")
}

// TestIntegrationPrepareWorktreeReconcilesOwnedPaths verifies that PrepareWorktree
// reverts modified tracked files, removes untracked orphans, skips paths untracked
// at HEAD, and preserves gitignored files.
func TestIntegrationPrepareWorktreeReconcilesOwnedPaths(t *testing.T) {
	t.Parallel()

	dir := initTestRepo(t)

	// A tracked file in an owned path, plus a .gitignore that must be respected.
	gittest.WriteFile(t, dir, "data/assessments/tracked.json", `{"v":1}`)
	gittest.WriteFile(t, dir, "data/assessments/.gitignore", "ignored.txt\n")
	gittest.Run(t, dir, "add", "-A")
	gittest.Run(t, dir, "commit", "-m", "chore: seed tracked file")

	// Modify the tracked file (must be reverted to HEAD).
	gittest.WriteFile(t, dir, "data/assessments/tracked.json", `{"v":999}`)
	// Add an untracked orphan (must be removed).
	gittest.WriteFile(t, dir, "data/assessments/orphan.json", `{"o":1}`)
	// Add a gitignored file (must be preserved).
	gittest.WriteFile(t, dir, "data/assessments/ignored.txt", "keep me")
	// An owned group with no tracked content at HEAD must not cause an error;
	// its untracked content is still cleaned.
	gittest.WriteFile(t, dir, "data/audit/late.json", `{"late":1}`)

	cfg := publish.Config{
		Target: publish.Target{Remote: "origin", Branch: "main"},
		Level:  publish.LevelCommit,
	}
	s := publish.NewService(cfg, git.NewWriter(dir, git.Committer{}))

	require.NoError(t, s.PrepareWorktree(t.Context(), createCommitGroup()))

	// Modified tracked file reverted to HEAD content.
	// tracked.json lives under the test's own temp dir.
	reverted, err := os.ReadFile(filepath.Join(dir, "data/assessments/tracked.json")) //nolint:gosec // test-only path
	require.NoError(t, err)
	assert.JSONEq(t, `{"v":1}`, string(reverted))

	// Untracked orphan removed.
	assert.NoFileExists(t, filepath.Join(dir, "data/assessments/orphan.json"))

	// Gitignored file preserved (clean without -x must not remove it).
	assert.FileExists(t, filepath.Join(dir, "data/assessments/ignored.txt"))

	// Untracked-at-HEAD owned audit orphan is cleaned as well.
	assert.NoFileExists(t, filepath.Join(dir, "data/audit/late.json"))
}

// TestIntegrationVerifyBranch verifies branch validation against a real repository:
// the matching branch passes, a wrong branch fails, and a detached HEAD (detected
// via git's exit code) yields a clear error.
func TestIntegrationVerifyBranch(t *testing.T) {
	t.Parallel()

	t.Run("matching branch passes", func(t *testing.T) {
		t.Parallel()

		dir := initTestRepo(t)
		cfg := publish.Config{
			Target: publish.Target{Remote: "origin", Branch: "main"},
			Level:  publish.LevelCommit,
		}
		s := publish.NewService(cfg, git.NewWriter(dir, git.Committer{}))

		require.NoError(t, s.VerifyBranch(t.Context()))
	})

	t.Run("wrong branch fails naming both branches", func(t *testing.T) {
		t.Parallel()

		dir := initTestRepo(t)
		gittest.Run(t, dir, "checkout", "-b", "feature-x")
		cfg := publish.Config{
			Target: publish.Target{Remote: "origin", Branch: "main"},
			Level:  publish.LevelCommit,
		}
		s := publish.NewService(cfg, git.NewWriter(dir, git.Committer{}))

		err := s.VerifyBranch(t.Context())
		require.Error(t, err)
		require.ErrorIs(t, err, publish.ErrBranchMismatch)
		assert.Contains(t, err.Error(), "feature-x")
		assert.Contains(t, err.Error(), "main")
	})

	t.Run("detached HEAD returns a clear error", func(t *testing.T) {
		t.Parallel()

		dir := initTestRepo(t)
		gittest.Run(t, dir, "commit", "--allow-empty", "-m", "chore: second")
		// Detach HEAD onto the previous commit.
		gittest.Run(t, dir, "checkout", "--detach", "HEAD~1")
		cfg := publish.Config{
			Target: publish.Target{Remote: "origin", Branch: "main"},
			Level:  publish.LevelCommit,
		}
		s := publish.NewService(cfg, git.NewWriter(dir, git.Committer{}))

		err := s.VerifyBranch(t.Context())
		require.Error(t, err)
		require.ErrorIs(t, err, git.ErrDetachedHEAD)
	})
}

// TestIntegrationVerifyCleanIndexForPush verifies the clean-index check against
// real `git diff --cached` exit codes: a clean index passes and a dirty index fails.
func TestIntegrationVerifyCleanIndexForPush(t *testing.T) {
	t.Parallel()

	t.Run("clean index passes", func(t *testing.T) {
		t.Parallel()

		dir := initTestRepo(t)
		seedCommitGroupDirs(t, dir)
		cfg := publish.Config{
			Target: publish.Target{Remote: "origin", Branch: "main"},
			Level:  publish.LevelPush,
		}
		s := publish.NewService(cfg, git.NewWriter(dir, git.Committer{}))

		require.NoError(t, s.VerifyCleanIndexForPush(t.Context()))
	})

	t.Run("dirty index fails", func(t *testing.T) {
		t.Parallel()

		dir := initTestRepo(t)
		seedCommitGroupDirs(t, dir)
		gittest.WriteFile(t, dir, "data/assessments/staged.json", `{"s":1}`)
		gittest.Run(t, dir, "add", "data/assessments/staged.json")
		cfg := publish.Config{
			Target: publish.Target{Remote: "origin", Branch: "main"},
			Level:  publish.LevelPush,
		}
		s := publish.NewService(cfg, git.NewWriter(dir, git.Committer{}))

		err := s.VerifyCleanIndexForPush(t.Context())
		require.Error(t, err)
		require.ErrorIs(t, err, publish.ErrDirtyIndex)
	})
}

// TestIntegrationPushAdvancesRemote verifies that LevelPush actually advances the
// bare remote's branch ref to the locally committed HEAD.
func TestIntegrationPushAdvancesRemote(t *testing.T) {
	t.Parallel()

	remote := gittest.InitBareRemote(t)
	dir := initTestRepo(t)
	seedCommitGroupDirs(t, dir)
	gittest.Run(t, dir, "remote", "add", "origin", remote)
	// Seed the remote with current history so the push is a fast-forward.
	gittest.Run(t, dir, "push", "origin", "main")
	remoteBefore := strings.TrimSpace(gittest.Run(t, remote, "rev-parse", "refs/heads/main"))

	gittest.WriteFile(t, dir, "data/assessments/a.json", `{"a":1}`)

	cfg := publish.Config{
		Target: publish.Target{Remote: "origin", Branch: "main"},
		Level:  publish.LevelPush,
	}
	s := publish.NewService(cfg, git.NewWriter(dir, git.Committer{}))

	require.NoError(t, s.Run(t.Context(), createCommitGroup(), testMessageForCommitGroup))

	localHead := gittest.HeadSHA(t, dir)
	remoteAfter := strings.TrimSpace(gittest.Run(t, remote, "rev-parse", "refs/heads/main"))
	assert.NotEqual(t, remoteBefore, remoteAfter, "remote ref should have advanced")
	assert.Equal(t, localHead, remoteAfter, "remote ref should match local HEAD")
}

// TestIntegrationPushNoChangesLeavesRemoteUntouched verifies that with no group
// content, nothing is committed and the remote ref is unchanged.
func TestIntegrationPushNoChangesLeavesRemoteUntouched(t *testing.T) {
	t.Parallel()

	remote := gittest.InitBareRemote(t)
	dir := initTestRepo(t)
	seedCommitGroupDirs(t, dir)
	gittest.Run(t, dir, "remote", "add", "origin", remote)
	gittest.Run(t, dir, "push", "origin", "main")

	start := gittest.HeadSHA(t, dir)
	remoteBefore := strings.TrimSpace(gittest.Run(t, remote, "rev-parse", "refs/heads/main"))

	cfg := publish.Config{
		Target: publish.Target{Remote: "origin", Branch: "main"},
		Level:  publish.LevelPush,
	}
	s := publish.NewService(cfg, git.NewWriter(dir, git.Committer{}))

	require.NoError(t, s.Run(t.Context(), createCommitGroup(), testMessageForCommitGroup))

	assert.Equal(t, start, gittest.HeadSHA(t, dir), "HEAD should not move")
	remoteAfter := strings.TrimSpace(gittest.Run(t, remote, "rev-parse", "refs/heads/main"))
	assert.Equal(t, remoteBefore, remoteAfter, "remote ref should be untouched")
}

// TestIntegrationPushRollbackOnNonFastForward verifies that when the remote has
// advanced concurrently, the rejected push rolls local HEAD back to the start SHA.
func TestIntegrationPushRollbackOnNonFastForward(t *testing.T) {
	t.Parallel()

	remote := gittest.InitBareRemote(t)

	// Init, commit and push our test repo to the remote.
	dir := initTestRepo(t)
	seedCommitGroupDirs(t, dir)
	gittest.Run(t, dir, "remote", "add", "origin", remote)
	gittest.Run(t, dir, "push", "origin", "main")
	startHash := gittest.HeadSHA(t, dir)

	// Set main as main branch of the remote.
	gittest.Run(t, remote, "symbolic-ref", "HEAD", "refs/heads/main")

	// Advance remote with a separate repo independent from our original test repo.
	other := t.TempDir()
	gittest.Run(t, other, "clone", remote, ".")
	gittest.Run(t, other, "commit", "--allow-empty", "-m", "chore: concurrent")
	gittest.Run(t, other, "push", "origin", "HEAD:refs/heads/main")
	hashAfterChange := strings.TrimSpace(gittest.Run(t, remote, "rev-parse", "refs/heads/main"))

	gittest.WriteFile(t, dir, "data/assessments/a.json", `{"a":1}`)

	cfg := publish.Config{
		Target: publish.Target{Remote: "origin", Branch: "main"},
		Level:  publish.LevelPush,
	}
	s := publish.NewService(cfg, git.NewWriter(dir, git.Committer{}))

	err := s.Run(t.Context(), createCommitGroup(), testMessageForCommitGroup)
	require.Error(t, err)
	require.ErrorIs(t, err, git.ErrNonFastForward)

	// Local HEAD was rolled back and the remote is unchanged.
	assert.Equal(t, startHash, gittest.HeadSHA(t, dir), "local HEAD should be rolled back")
	remoteHashAfterRollback := strings.TrimSpace(gittest.Run(t, remote, "rev-parse", "refs/heads/main"))
	assert.Equal(t, hashAfterChange, remoteHashAfterRollback, "remote ref must not have changed")

	// The soft reset preserves the committed change: it is staged, not lost.
	staged := gittest.Run(t, dir, "diff", "--cached", "--name-only")
	assert.Contains(t, staged, "data/assessments/a.json", "rolled-back change must remain staged")
}

// TestIntegrationFullPipelineHappyPath chains the four Service steps in the same
// order as the production pipeline against a real repo and remote, verifying that a
// clean run commits each non-empty group and fast-forwards the remote to local HEAD.
func TestIntegrationFullPipelineHappyPath(t *testing.T) {
	t.Parallel()

	remote := gittest.InitBareRemote(t)
	dir := initTestRepo(t)
	seedCommitGroupDirs(t, dir)
	gittest.Run(t, dir, "remote", "add", "origin", remote)
	// Seed the remote with current history so the push is a fast-forward.
	gittest.Run(t, dir, "push", "origin", "main")
	remoteBefore := strings.TrimSpace(gittest.Run(t, remote, "rev-parse", "refs/heads/main"))

	cfg := publish.Config{
		Target: publish.Target{Remote: "origin", Branch: "main"},
		Level:  publish.LevelPush,
	}
	s := publish.NewService(cfg, git.NewWriter(dir, git.Committer{}))
	groups := createCommitGroup()

	require.NoError(t, s.VerifyBranch(t.Context()))
	require.NoError(t, s.PrepareWorktree(t.Context(), groups))
	require.NoError(t, s.VerifyCleanIndexForPush(t.Context()))

	gittest.WriteFile(t, dir, "data/assessments/a.json", `{"a":1}`)
	gittest.WriteFile(t, dir, "data/audit/b.json", `{"b":2}`)

	require.NoError(t, s.Run(t.Context(), groups, testMessageForCommitGroup))

	// One commit per group on top of the seeded history, newest first.
	subjects := gittest.GetCommitSubjects(t, dir)
	require.Equal(t, []string{
		"data(audit): update",
		"data(assessments): update",
		"chore: seed group dirs",
		"chore: init",
	}, subjects)

	// The remote fast-forwarded to the local HEAD.
	localHead := gittest.HeadSHA(t, dir)
	remoteAfter := strings.TrimSpace(gittest.Run(t, remote, "rev-parse", "refs/heads/main"))
	assert.NotEqual(t, remoteBefore, remoteAfter, "remote ref should have advanced")
	assert.Equal(t, localHead, remoteAfter, "remote ref should match local HEAD")

	// The index is clean after a successful run: nothing left staged.
	staged := strings.TrimSpace(gittest.Run(t, dir, "diff", "--cached", "--name-only"))
	assert.Empty(t, staged, "index should be clean after a successful push")
}

// TestIntegrationFullPipelineCommitLevelHappyPath chains the Service steps in
// production order at LevelCommit: it commits each non-empty group locally and
// performs no push, leaving the worktree clean and the remote untouched.
func TestIntegrationFullPipelineCommitLevelHappyPath(t *testing.T) {
	t.Parallel()

	remote := gittest.InitBareRemote(t)
	dir := initTestRepo(t)
	seedCommitGroupDirs(t, dir)
	gittest.Run(t, dir, "remote", "add", "origin", remote)
	// Seed the remote so we have a baseline ref to compare against.
	gittest.Run(t, dir, "push", "origin", "main")
	remoteBefore := strings.TrimSpace(gittest.Run(t, remote, "rev-parse", "refs/heads/main"))

	cfg := publish.Config{
		Target: publish.Target{Remote: "origin", Branch: "main"},
		Level:  publish.LevelCommit,
	}
	s := publish.NewService(cfg, git.NewWriter(dir, git.Committer{}))
	groups := createCommitGroup()

	require.NoError(t, s.VerifyBranch(t.Context()))
	require.NoError(t, s.PrepareWorktree(t.Context(), groups))
	require.NoError(t, s.VerifyCleanIndexForPush(t.Context()))

	gittest.WriteFile(t, dir, "data/assessments/a.json", `{"a":1}`)
	gittest.WriteFile(t, dir, "data/audit/b.json", `{"b":2}`)

	require.NoError(t, s.Run(t.Context(), groups, testMessageForCommitGroup))

	// One commit per group on top of the seeded history, newest first.
	subjects := gittest.GetCommitSubjects(t, dir)
	require.Equal(t, []string{
		"data(audit): update",
		"data(assessments): update",
		"chore: seed group dirs",
		"chore: init",
	}, subjects)

	// The commits are local only; the worktree and index are clean afterwards.
	status := strings.TrimSpace(gittest.Run(t, dir, "status", "--porcelain"))
	assert.Empty(t, status, "worktree should be clean after commit-level run")

	// No push happened: the remote ref is unchanged despite local commits.
	remoteAfter := strings.TrimSpace(gittest.Run(t, remote, "rev-parse", "refs/heads/main"))
	assert.Equal(t, remoteBefore, remoteAfter, "remote ref must be untouched at commit level")
}
