package publish_test

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/gardenlinux/glvd2/internal/git"
	"github.com/gardenlinux/glvd2/internal/publish"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeGit is a scriptable gitClient mock that records calls.
type fakeGit struct {
	currentBranch    string
	currentBranchErr error
	branchCallCount  int

	heads        []string // successive RevParseHEAD return values
	headIdx      int
	headErr      error // returned by RevParseHEAD once headErrAt calls have been made
	headErrAt    int   // 1-based call index at which RevParseHEAD returns headErr
	headCalls    int
	isIndexClean bool
	indexErr     error

	stagedResult  map[string]bool // key: first path -> staged?
	stagedErr     error
	addErr        error
	commitErr     error // returned by Commit for the group whose first path matches commitErrPath
	commitErrPath string
	pushErr       error
	resetErr      error

	changedResult []string
	changedErr    error
	restoreErr    error

	// recorded calls
	committed    []string // group first-path per commit
	resetCalls   []string
	pushCalls    int
	restoreCalls int
}

func (f *fakeGit) CurrentBranch(_ context.Context) (string, error) {
	f.branchCallCount++
	return f.currentBranch, f.currentBranchErr
}

func (f *fakeGit) RevParseHEAD(_ context.Context) (string, error) {
	f.headCalls++
	if f.headErr != nil && f.headCalls == f.headErrAt {
		return "", f.headErr
	}
	if f.headIdx >= len(f.heads) {
		return f.heads[len(f.heads)-1], nil
	}
	h := f.heads[f.headIdx]
	f.headIdx++
	return h, nil
}

func (f *fakeGit) IsIndexClean(_ context.Context) (bool, error) {
	return f.isIndexClean, f.indexErr
}

func (f *fakeGit) AddPaths(_ context.Context, _ ...string) error {
	return f.addErr
}

func (f *fakeGit) HasStagedChanges(_ context.Context, paths ...string) (bool, error) {
	if f.stagedErr != nil {
		return false, f.stagedErr
	}
	if f.stagedResult == nil {
		return true, nil
	}
	return f.stagedResult[paths[0]], nil
}

func (f *fakeGit) Commit(_ context.Context, _ string, paths ...string) error {
	if f.commitErr != nil && paths[0] == f.commitErrPath {
		return f.commitErr
	}
	f.committed = append(f.committed, paths[0])
	return nil
}

func (f *fakeGit) ResetSoft(_ context.Context, sha string) error {
	f.resetCalls = append(f.resetCalls, sha)
	return f.resetErr
}

func (f *fakeGit) PushFastForward(_ context.Context, _, _ string) error {
	f.pushCalls++
	return f.pushErr
}

func (f *fakeGit) ChangesInPaths(_ context.Context, _ ...string) ([]string, error) {
	return f.changedResult, f.changedErr
}

func (f *fakeGit) RestorePaths(_ context.Context, _ ...string) error {
	f.restoreCalls++
	return f.restoreErr
}

func testCfg() publish.Config {
	return publish.Config{
		Target: publish.Target{Remote: "origin", Branch: "main"},
		Level:  publish.LevelNone, // overridden by specific tests
	}
}

func TestRunNoOp(t *testing.T) {
	t.Parallel()

	f := &fakeGit{heads: []string{"aaaa"}}
	s := publish.NewService(testCfg(), f)

	require.NoError(t, s.Run(t.Context(), createCommitGroup(), testMessageForCommitGroup))
	assert.Empty(t, f.committed)
	assert.Zero(t, f.pushCalls)
	assert.Zero(t, f.headCalls, "LevelNone must not touch git")
}

func TestRunEmptyGroups(t *testing.T) {
	t.Parallel()

	for _, level := range []publish.Level{publish.LevelCommit, publish.LevelPush} {
		t.Run(level.String(), func(t *testing.T) {
			t.Parallel()

			f := &fakeGit{heads: []string{"start"}}
			cfg := testCfg()
			cfg.Level = level
			s := publish.NewService(cfg, f)

			require.NoError(t, s.Run(t.Context(), nil, testMessageForCommitGroup))
			assert.Empty(t, f.committed)
			assert.Zero(t, f.pushCalls)
			assert.Empty(t, f.resetCalls)
		})
	}
}

func TestRunErrorCapturingStartFails(t *testing.T) {
	t.Parallel()

	// RevParseHEAD fails on the first call (capturing start SHA).
	f := &fakeGit{heads: []string{"start"}, headErr: errors.New("no head"), headErrAt: 1}
	cfg := testCfg()
	cfg.Level = publish.LevelCommit
	s := publish.NewService(cfg, f)

	err := s.Run(t.Context(), createCommitGroup(), testMessageForCommitGroup)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "capturing start commit")
	// No commit or rollback should have happened.
	assert.Empty(t, f.committed)
	assert.Empty(t, f.resetCalls)
}

func TestRunRollbackOnAddError(t *testing.T) {
	t.Parallel()

	f := &fakeGit{heads: []string{"start"}, addErr: errors.New("add failed")}
	cfg := testCfg()
	cfg.Level = publish.LevelCommit
	s := publish.NewService(cfg, f)

	err := s.Run(t.Context(), createCommitGroup(), testMessageForCommitGroup)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "staging group")
	assert.Equal(t, []string{"start"}, f.resetCalls)
	assert.Empty(t, f.committed)
}

func TestRunRollbackOnHasStagedChangesError(t *testing.T) {
	t.Parallel()

	f := &fakeGit{heads: []string{"start"}, stagedErr: errors.New("diff failed")}
	cfg := testCfg()
	cfg.Level = publish.LevelCommit
	s := publish.NewService(cfg, f)

	err := s.Run(t.Context(), createCommitGroup(), testMessageForCommitGroup)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "checking staged content")
	assert.Equal(t, []string{"start"}, f.resetCalls)
	assert.Empty(t, f.committed)
}

func TestRunRollbackOnHeadResolveBeforePush(t *testing.T) {
	t.Parallel()

	// First RevParseHEAD (start capture) succeeds; second (before push) fails.
	f := &fakeGit{heads: []string{"start"}, headErr: errors.New("detached"), headErrAt: 2}
	cfg := testCfg()
	cfg.Level = publish.LevelPush
	s := publish.NewService(cfg, f)

	err := s.Run(t.Context(), createCommitGroup(), testMessageForCommitGroup)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolving HEAD before push")
	assert.Equal(t, []string{"start"}, f.resetCalls)
	assert.Zero(t, f.pushCalls)
}

func TestRunCommitsInOrder(t *testing.T) {
	t.Parallel()

	f := &fakeGit{heads: []string{"start"}}
	cfg := testCfg()
	cfg.Level = publish.LevelCommit
	s := publish.NewService(cfg, f)

	require.NoError(t, s.Run(t.Context(), createCommitGroup(), testMessageForCommitGroup))
	assert.Equal(t, []string{"data/assessments", "data/audit"}, f.committed)
}

func TestRunSkipsEmptyGroup(t *testing.T) {
	t.Parallel()

	f := &fakeGit{
		heads: []string{"start"},
		stagedResult: map[string]bool{
			"data/assessments": false,
			"data/audit":       true,
		},
	}
	cfg := testCfg()
	cfg.Level = publish.LevelCommit
	s := publish.NewService(cfg, f)

	require.NoError(t, s.Run(t.Context(), createCommitGroup(), testMessageForCommitGroup))
	assert.Equal(t, []string{"data/audit"}, f.committed)
}

func TestRunRollbackOnCommitError(t *testing.T) {
	t.Parallel()

	f := &fakeGit{
		heads:         []string{"start"},
		commitErr:     errors.New("boom"),
		commitErrPath: "data/audit",
	}
	cfg := testCfg()
	cfg.Level = publish.LevelCommit
	s := publish.NewService(cfg, f)

	err := s.Run(t.Context(), createCommitGroup(), testMessageForCommitGroup)
	require.Error(t, err)
	assert.Equal(t, []string{"start"}, f.resetCalls)
	// assessments committed before the failing audit commit.
	assert.Equal(t, []string{"data/assessments"}, f.committed)
}

func TestRunPushSkippedWhenHeadUnchanged(t *testing.T) {
	t.Parallel()

	// All groups empty => HEAD unchanged => push skipped.
	f := &fakeGit{
		heads: []string{"start", "start"},
		stagedResult: map[string]bool{
			"data/assessments": false,
			"data/audit":       false,
		},
	}
	cfg := testCfg()
	cfg.Level = publish.LevelPush
	s := publish.NewService(cfg, f)

	require.NoError(t, s.Run(t.Context(), createCommitGroup(), testMessageForCommitGroup))
	assert.Zero(t, f.pushCalls)
	assert.Empty(t, f.resetCalls)
}

func TestRunPushWhenAdvanced(t *testing.T) {
	t.Parallel()

	f := &fakeGit{heads: []string{"start", "head2"}}
	cfg := testCfg()
	cfg.Level = publish.LevelPush
	s := publish.NewService(cfg, f)

	require.NoError(t, s.Run(t.Context(), createCommitGroup(), testMessageForCommitGroup))
	assert.Equal(t, 1, f.pushCalls)
	assert.Empty(t, f.resetCalls)
}

func TestRunRollbackOnNonFastForward(t *testing.T) {
	t.Parallel()

	f := &fakeGit{
		heads:   []string{"start", "head2"},
		pushErr: git.ErrNonFastForward,
	}
	cfg := testCfg()
	cfg.Level = publish.LevelPush
	s := publish.NewService(cfg, f)

	err := s.Run(t.Context(), createCommitGroup(), testMessageForCommitGroup)
	require.Error(t, err)
	require.ErrorIs(t, err, git.ErrNonFastForward)
	assert.Equal(t, []string{"start"}, f.resetCalls)
}

func TestRunRollbackOnPushError(t *testing.T) {
	t.Parallel()

	f := &fakeGit{
		heads:   []string{"start", "head2"},
		pushErr: errors.New("network down"),
	}
	cfg := testCfg()
	cfg.Level = publish.LevelPush
	s := publish.NewService(cfg, f)

	err := s.Run(t.Context(), createCommitGroup(), testMessageForCommitGroup)
	require.Error(t, err)
	assert.Equal(t, []string{"start"}, f.resetCalls)
}

func TestRunRollbackFailurePreservesCause(t *testing.T) {
	t.Parallel()

	cause := git.ErrNonFastForward
	f := &fakeGit{
		heads:    []string{"start", "head2"},
		pushErr:  cause,
		resetErr: errors.New("reset failed"),
	}
	cfg := testCfg()
	cfg.Level = publish.LevelPush
	s := publish.NewService(cfg, f)

	err := s.Run(t.Context(), createCommitGroup(), testMessageForCommitGroup)
	require.Error(t, err)
	require.ErrorIs(t, err, cause)
	assert.Contains(t, err.Error(), "reset failed")
}

func TestVerifyBranch(t *testing.T) {
	t.Parallel()

	for _, level := range []publish.Level{publish.LevelCommit, publish.LevelPush} {
		t.Run(level.String()+"/matching branch succeeds", func(t *testing.T) {
			t.Parallel()

			f := &fakeGit{currentBranch: "main"}
			cfg := testCfg()
			cfg.Level = level
			s := publish.NewService(cfg, f)

			require.NoError(t, s.VerifyBranch(t.Context()))
			assert.Equal(t, 1, f.branchCallCount)
		})

		t.Run(level.String()+"/wrong branch returns error naming both branches", func(t *testing.T) {
			t.Parallel()

			f := &fakeGit{currentBranch: "feature-x"}
			cfg := testCfg()
			cfg.Level = level
			s := publish.NewService(cfg, f)

			err := s.VerifyBranch(t.Context())
			require.Error(t, err)
			require.ErrorIs(t, err, publish.ErrBranchMismatch)
			assert.Contains(t, err.Error(), "feature-x")
			assert.Contains(t, err.Error(), "main")
			assert.Equal(t, 1, f.branchCallCount)
		})

		t.Run(level.String()+"/detached HEAD returns clear error", func(t *testing.T) {
			t.Parallel()

			f := &fakeGit{currentBranchErr: git.ErrDetachedHEAD}
			cfg := testCfg()
			cfg.Level = level
			s := publish.NewService(cfg, f)

			err := s.VerifyBranch(t.Context())
			require.Error(t, err)
			require.ErrorIs(t, err, git.ErrDetachedHEAD)
			assert.Equal(t, 1, f.branchCallCount)
		})
	}

	t.Run("LevelNone skips branch check", func(t *testing.T) {
		t.Parallel()

		// currentBranch deliberately wrong to confirm it is never called.
		f := &fakeGit{currentBranch: "wrong-branch"}
		cfg := testCfg()
		cfg.Level = publish.LevelNone
		s := publish.NewService(cfg, f)

		require.NoError(t, s.VerifyBranch(t.Context()))
		assert.Zero(t, f.branchCallCount)
	})
}

func TestVerifyCleanIndexForPush(t *testing.T) {
	t.Parallel()

	t.Run("LevelPush/dirty index fails", func(t *testing.T) {
		t.Parallel()

		f := &fakeGit{isIndexClean: false}
		cfg := testCfg()
		cfg.Level = publish.LevelPush
		s := publish.NewService(cfg, f)

		err := s.VerifyCleanIndexForPush(t.Context())
		require.Error(t, err)
		require.ErrorIs(t, err, publish.ErrDirtyIndex)
	})

	t.Run("LevelPush/index error is wrapped", func(t *testing.T) {
		t.Parallel()

		f := &fakeGit{indexErr: errors.New("diff failed")}
		cfg := testCfg()
		cfg.Level = publish.LevelPush
		s := publish.NewService(cfg, f)

		err := s.VerifyCleanIndexForPush(t.Context())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "checking clean index")
	})

	t.Run("LevelPush/clean index passes", func(t *testing.T) {
		t.Parallel()

		f := &fakeGit{isIndexClean: true}
		cfg := testCfg()
		cfg.Level = publish.LevelPush
		s := publish.NewService(cfg, f)

		require.NoError(t, s.VerifyCleanIndexForPush(t.Context()))
	})

	for _, level := range []publish.Level{publish.LevelCommit, publish.LevelNone} {
		t.Run(level.String()+"/skips check entirely", func(t *testing.T) {
			t.Parallel()

			// isIndexClean is false to confirm the check is never invoked.
			f := &fakeGit{isIndexClean: false}
			cfg := testCfg()
			cfg.Level = level
			s := publish.NewService(cfg, f)

			require.NoError(t, s.VerifyCleanIndexForPush(t.Context()))
		})
	}
}

func TestPrepareWorktree(t *testing.T) {
	t.Parallel()

	t.Run("RestorePaths is always called regardless of level or dirtiness", func(t *testing.T) {
		t.Parallel()

		for _, level := range []publish.Level{publish.LevelNone, publish.LevelCommit, publish.LevelPush} {
			for _, dirty := range []bool{false, true} {
				t.Run(level.String()+"/dirty="+strconv.FormatBool(dirty), func(t *testing.T) {
					t.Parallel()

					var changed []string
					if dirty {
						changed = []string{" M data/assessments/cve-2026-0123.json"}
					}
					f := &fakeGit{changedResult: changed}
					cfg := testCfg()
					cfg.Level = level
					s := publish.NewService(cfg, f)

					require.NoError(t, s.PrepareWorktree(t.Context(), createCommitGroup()))
					assert.Equal(t, 1, f.restoreCalls, "RestorePaths must always be called")
				})
			}
		}
	})

	t.Run("empty groups: no git calls made", func(t *testing.T) {
		t.Parallel()

		f := &fakeGit{}
		s := publish.NewService(testCfg(), f)

		require.NoError(t, s.PrepareWorktree(t.Context(), nil))
		assert.Zero(t, f.restoreCalls)
	})

	t.Run("ChangesInPaths error is returned", func(t *testing.T) {
		t.Parallel()

		f := &fakeGit{changedErr: errors.New("git failed")}
		s := publish.NewService(testCfg(), f)

		err := s.PrepareWorktree(t.Context(), createCommitGroup())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "detecting pre-existing changes")
		assert.Zero(t, f.restoreCalls, "RestorePaths must not be called when ChangesInPaths fails")
	})

	t.Run("RestorePaths error is returned", func(t *testing.T) {
		t.Parallel()

		f := &fakeGit{restoreErr: errors.New("restore failed")}
		s := publish.NewService(testCfg(), f)

		err := s.PrepareWorktree(t.Context(), createCommitGroup())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "reconciling owned paths to HEAD")
	})
}
