package publish

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/gardenlinux/glvd2/internal/git"
)

var (
	ErrBranchMismatch = errors.New("current branch does not match configured branch")
	ErrDirtyIndex     = errors.New("index is not clean")
)

// Target is the destination for the git push.
type Target struct {
	Remote string
	Branch string
}

// Config contains the configuration for the pipeline run.
type Config struct {
	Target Target // fast-forward push destination (remote + branch)
	Level  Level  // how far publishing goes (none | commit | push)
}

// gitClient is the minimal git surface the Service depends on.
type gitClient interface {
	CurrentBranch(ctx context.Context) (string, error)
	RevParseHEAD(ctx context.Context) (string, error)
	IsIndexClean(ctx context.Context) (bool, error)
	AddPaths(ctx context.Context, paths ...string) error
	HasStagedChanges(ctx context.Context, paths ...string) (bool, error)
	Commit(ctx context.Context, message string, paths ...string) error
	ResetSoft(ctx context.Context, sha string) error
	PushFastForward(ctx context.Context, remote, branch string) error
	ChangesInPaths(ctx context.Context, paths ...string) ([]string, error)
	RestorePaths(ctx context.Context, paths ...string) error
}

// Service commits and pushes artifact groups according to the publish level.
type Service struct {
	git gitClient
	cfg Config
}

func NewService(cfg Config, g gitClient) *Service {
	return &Service{
		git: g,
		cfg: cfg,
	}
}

// PrepareWorktree reconciles all commit group paths to HEAD before the actual run.
func (s *Service) PrepareWorktree(ctx context.Context, commitGroups []CommitGroup) error {
	var allPaths []string
	for _, g := range commitGroups {
		allPaths = append(allPaths, g.Paths...)
	}
	if len(allPaths) == 0 {
		return nil
	}

	changes, err := s.git.ChangesInPaths(ctx, allPaths...)
	if err != nil {
		return fmt.Errorf("detecting pre-existing changes: %w", err)
	}
	if len(changes) > 0 {
		slog.Warn(
			"unexpected pre-existing changes in GLVD2 owned paths before pipeline run - "+
				"reconciling to HEAD",
			slog.Any("changed", changes),
		)
	}

	if err = s.git.RestorePaths(ctx, allPaths...); err != nil {
		return fmt.Errorf("reconciling owned paths to HEAD: %w", err)
	}

	return nil
}

// VerifyBranch checks that HEAD is on the configured branch. No-op at [LevelNone].
func (s *Service) VerifyBranch(ctx context.Context) error {
	if s.cfg.Level == LevelNone {
		return nil
	}

	branch, err := s.git.CurrentBranch(ctx)
	if err != nil {
		if errors.Is(err, git.ErrDetachedHEAD) {
			return fmt.Errorf(
				"committing requires being on a branch, but HEAD is detached: "+
					"check out %q before running: %w",
				s.cfg.Target.Branch, git.ErrDetachedHEAD,
			)
		}
		return fmt.Errorf("checking current branch: %w", err)
	}
	if branch != s.cfg.Target.Branch {
		return fmt.Errorf(
			"%w: current branch %q, configured branch %q: "+
				"check out %q before running",
			ErrBranchMismatch, branch, s.cfg.Target.Branch, s.cfg.Target.Branch,
		)
	}

	return nil
}

// VerifyCleanIndexForPush checks that no foreign staged content is present.
// Must run after [PrepareWorktree]. No-op unless cfg.Level is [LevelPush].
func (s *Service) VerifyCleanIndexForPush(ctx context.Context) error {
	if s.cfg.Level != LevelPush {
		return nil
	}

	isClean, err := s.git.IsIndexClean(ctx)
	if err != nil {
		return fmt.Errorf("checking clean index: %w", err)
	}
	if !isClean {
		return fmt.Errorf(
			"%w: staged content present before run (Push level requires a clean index)",
			ErrDirtyIndex,
		)
	}

	return nil
}

// Run commits for each commit group (skipping empty ones) and optionally pushes,
// rolling back to the starting HEAD on failure. commitMessageFor supplies the commit
// message for a group by its name. isLastCommit is true for the last group that will actually
// commit, letting the caller mark run completion on that commit. It is invoked only for
// groups with staged changes, after the pipeline run when post-run state is available.
func (s *Service) Run(
	ctx context.Context,
	commitGroups []CommitGroup,
	commitMessageFor func(name string, isLastCommit bool) string,
) error {
	if s.cfg.Level == LevelNone {
		slog.Info("skipping committing and publishing step", slog.String("publishLevel", s.cfg.Level.String()))
		return nil
	}

	startSHA, err := s.git.RevParseHEAD(ctx)
	if err != nil {
		return fmt.Errorf("capturing start commit: %w", err)
	}

	// Build the ordered list of commits to make, with empty groups dropped and each message already resolved.
	planned, err := s.planCommits(ctx, commitGroups, commitMessageFor)
	if err != nil {
		return s.rollback(ctx, startSHA, err)
	}

	for _, pc := range planned {
		if cErr := s.git.Commit(ctx, pc.message, pc.group.Paths...); cErr != nil {
			return s.rollback(ctx, startSHA, fmt.Errorf("committing group %q: %w", pc.group.Name, cErr))
		}

		slog.Info("committed group",
			slog.String("group", pc.group.Name),
			slog.Any("paths", pc.group.Paths))
	}

	if s.cfg.Level == LevelPush {
		if pErr := s.pushIfAdvanced(ctx, startSHA); pErr != nil {
			return pErr
		}
	}

	return nil
}

// plannedCommit is a commit the run will create: a group that has staged changes paired
// with its resolved message.
type plannedCommit struct {
	group   CommitGroup
	message string
}

// planCommits stages each group and returns the ordered commits to create, skipping groups
// with no staged changes and resolving each message with isLastCommit set on the last one.
// Staging all groups up front is safe because each commit is restricted to its group's paths.
func (s *Service) planCommits(
	ctx context.Context,
	commitGroups []CommitGroup,
	commitMessageFor func(name string, isLastCommit bool) string,
) ([]plannedCommit, error) {
	var toCommit []CommitGroup
	for _, commitGroup := range commitGroups {
		if err := s.git.AddPaths(ctx, commitGroup.Paths...); err != nil {
			return nil, fmt.Errorf("staging group %q: %w", commitGroup.Name, err)
		}

		hasStagedChanges, err := s.git.HasStagedChanges(ctx, commitGroup.Paths...)
		if err != nil {
			return nil, fmt.Errorf("checking staged content for group %q: %w", commitGroup.Name, err)
		}
		if !hasStagedChanges {
			slog.Info("skipping empty commit group",
				slog.String("group", commitGroup.Name),
				slog.Any("paths", commitGroup.Paths))
			continue
		}

		toCommit = append(toCommit, commitGroup)
	}

	planned := make([]plannedCommit, len(toCommit))
	for i, commitGroup := range toCommit {
		isLastCommit := i == len(toCommit)-1
		planned[i] = plannedCommit{
			group:   commitGroup,
			message: commitMessageFor(commitGroup.Name, isLastCommit),
		}
	}

	return planned, nil
}

// pushIfAdvanced pushes only when HEAD advanced past startSHA.
func (s *Service) pushIfAdvanced(ctx context.Context, startSHA string) error {
	head, err := s.git.RevParseHEAD(ctx)
	if err != nil {
		return s.rollback(ctx, startSHA, fmt.Errorf("resolving HEAD before push: %w", err))
	}

	if head == startSHA {
		slog.Info("nothing to push", slog.String("head", head))
		return nil
	}

	if pErr := s.git.PushFastForward(ctx, s.cfg.Target.Remote, s.cfg.Target.Branch); pErr != nil {
		if errors.Is(pErr, git.ErrNonFastForward) {
			slog.Error("push rejected: remote advanced since this run started (concurrent update); rolling back",
				slog.String("remote", s.cfg.Target.Remote),
				slog.String("branch", s.cfg.Target.Branch),
				slog.Any("error", pErr))
		} else {
			slog.Error("push failed; rolling back",
				slog.String("remote", s.cfg.Target.Remote),
				slog.String("branch", s.cfg.Target.Branch),
				slog.Any("error", pErr))
		}
		return s.rollback(ctx, startSHA, fmt.Errorf("pushing: %w", pErr))
	}

	slog.Info("pushed committed artifacts",
		slog.String("remote", s.cfg.Target.Remote),
		slog.String("branch", s.cfg.Target.Branch))

	return nil
}

// rollback soft-resets to startSHA, returning the original cause (joined with any reset error).
func (s *Service) rollback(ctx context.Context, startSHA string, cause error) error {
	if err := s.git.ResetSoft(ctx, startSHA); err != nil {
		slog.Error("rollback failed", slog.String("start_sha", startSHA), slog.Any("error", err))
		return errors.Join(cause, fmt.Errorf("rolling back to %s: %w", startSHA, err))
	}

	slog.Info("rolled back local commits", slog.String("start_sha", startSHA))

	return cause
}
