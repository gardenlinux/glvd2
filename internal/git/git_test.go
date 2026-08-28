package git_test

import (
	"testing"

	"github.com/gardenlinux/glvd2/internal/git"
	"github.com/gardenlinux/glvd2/internal/gittest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFindCommitByMessageAnchor_InvalidAnchor verifies that non-trailer-safe anchors
// (control-character injection and regex metacharacters) are rejected.
func TestFindCommitByMessageAnchor_InvalidAnchor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		anchor string
	}{
		{name: "empty", anchor: ""},
		{name: "leading dash", anchor: "-GLVD2-Baseline: true"},
		{name: "newline injection", anchor: "GLVD2-Baseline: true\nblub"},
		{name: "carriage return injection", anchor: "GLVD2-Baseline: true\rblub"},
		{name: "NUL byte injection", anchor: "GLVD2-Baseline: true\x00blub"},
		{name: "dot metacharacter", anchor: "GLVD2.Baseline: true"},
		{name: "star metacharacter", anchor: "GLVD2-Baseline: tru*"},
		{name: "bracket metacharacter", anchor: "GLVD2-Baseline: [true]"},
		{name: "backslash metacharacter", anchor: `GLVD2-Baseline: tru\e`},
		{name: "dollar metacharacter", anchor: "GLVD2-Baseline: true$"},
		{name: "caret metacharacter", anchor: "^GLVD2-Baseline: true"},
	}

	dir := t.TempDir()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := git.FindCommitByMessageAnchor(t.Context(), dir, tc.anchor)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "FindCommitByMessageAnchor")
		})
	}
}

// TestDiffFilesSince_InvalidCommitSHA verifies that DiffFilesSince rejects
// commit SHAs that are not valid hex strings.
func TestDiffFilesSince_InvalidCommitSHA(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		sha  string
	}{
		{name: "empty", sha: ""},
		{name: "uppercase hex", sha: "ABC123"},
		{name: "too short", sha: "abc"},
		{name: "contains dash", sha: "abc-123"},
		{name: "flag injection", sha: "--hard"},
		{name: "path traversal", sha: "../abc123"},
		{name: "newline injection", sha: "abc123\n"},
	}

	dir := t.TempDir()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := git.DiffFilesSince(t.Context(), dir, tc.sha, "data/cves")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "DiffFilesSince")
		})
	}
}

// TestDiffFilesSince_InvalidPathPrefix verifies that DiffFilesSince rejects
// path prefix arguments that could cause flag injection or path traversal.
func TestDiffFilesSince_InvalidPathPrefix(t *testing.T) {
	t.Parallel()

	// Use a valid SHA so validation reaches the path check.
	validSHA := "abc1234"

	tests := []struct {
		name       string
		pathPrefix string
	}{
		{name: "empty", pathPrefix: ""},
		{name: "starts with dash", pathPrefix: "-rf"},
		{name: "starts with double dash", pathPrefix: "--flag"},
		{name: "path traversal leading", pathPrefix: "../etc"},
		{name: "path traversal in middle", pathPrefix: "data/../etc"},
		{name: "path traversal only", pathPrefix: ".."},
	}

	dir := t.TempDir()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := git.DiffFilesSince(t.Context(), dir, validSHA, tc.pathPrefix)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "DiffFilesSince")
		})
	}
}

// TestShowFileAtCommit_InvalidCommitSHA verifies that ShowFileAtCommit rejects
// invalid commit SHAs before invoking git.
func TestShowFileAtCommit_InvalidCommitSHA(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		sha  string
	}{
		{name: "empty", sha: ""},
		{name: "uppercase hex", sha: "DEADBEEF"},
		{name: "too short", sha: "abc"},
		{name: "contains space", sha: "abc 123"},
		{name: "flag injection", sha: "--format=%H"},
		{name: "path traversal", sha: "../secret"},
	}

	dir := t.TempDir()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := git.ShowFileAtCommit(t.Context(), dir, tc.sha, "data/cves/file.json")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "ShowFileAtCommit")
		})
	}
}

// TestShowFileAtCommit_InvalidFilePath verifies that ShowFileAtCommit rejects
// file paths that could cause flag injection or path traversal.
func TestShowFileAtCommit_InvalidFilePath(t *testing.T) {
	t.Parallel()

	// Use a valid SHA so validation reaches the path check.
	validSHA := "abc1234"

	tests := []struct {
		name     string
		filePath string
	}{
		{name: "empty", filePath: ""},
		{name: "starts with dash", filePath: "-flag"},
		{name: "starts with double dash", filePath: "--flag"},
		{name: "path traversal leading", filePath: "../etc/passwd"},
		{name: "path traversal in middle", filePath: "data/../secret"},
		{name: "path traversal only", filePath: ".."},
	}

	dir := t.TempDir()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := git.ShowFileAtCommit(t.Context(), dir, validSHA, tc.filePath)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "ShowFileAtCommit")
		})
	}
}

// TestFindCommitByMessageAnchor exercises the full behavior of anchor-based
// commit lookup, including the $ anchor, -1 recency, and prefix filtering.
func TestFindCommitByMessageAnchor(t *testing.T) {
	t.Parallel()

	const anchor = "GLVD2-Baseline: true"

	t.Run("no commits returns empty string", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		sha, err := git.FindCommitByMessageAnchor(t.Context(), dir, anchor)
		require.NoError(t, err)
		assert.Empty(t, sha)
	})

	t.Run("no matching commits returns empty string", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		gittest.AddEmptyCommit(t, dir, "chore: first commit")
		gittest.AddEmptyCommit(t, dir, "chore: second commit")

		sha, err := git.FindCommitByMessageAnchor(t.Context(), dir, anchor)
		require.NoError(t, err)
		assert.Empty(t, sha)
	})

	t.Run("exact match returns SHA", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		want := gittest.AddEmptyCommit(t, dir, "chore: release\n\nGLVD2-Baseline: true")

		sha, err := git.FindCommitByMessageAnchor(t.Context(), dir, anchor)
		require.NoError(t, err)
		assert.Equal(t, want, sha)
	})

	t.Run("trailing text rejected by $ anchor", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		gittest.AddEmptyCommit(t, dir, "chore: release\n\nGLVD2-Baseline: true extra")

		sha, err := git.FindCommitByMessageAnchor(t.Context(), dir, anchor)
		require.NoError(t, err)
		assert.Empty(t, sha)
	})

	t.Run("trailing chars rejected by $ anchor", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		gittest.AddEmptyCommit(t, dir, "chore: release\n\nGLVD2-Baseline: truefalse")

		sha, err := git.FindCommitByMessageAnchor(t.Context(), dir, anchor)
		require.NoError(t, err)
		assert.Empty(t, sha)
	})

	t.Run("anchor in subject line is matched (--grep is not trailer-aware)", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		want := gittest.AddEmptyCommit(t, dir, "GLVD2-Baseline: true")

		sha, err := git.FindCommitByMessageAnchor(t.Context(), dir, anchor)
		require.NoError(t, err)
		assert.Equal(t, want, sha)
	})

	t.Run("most recent of multiple matching commits is returned", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		gittest.AddEmptyCommit(t, dir, "chore: first baseline\n\nGLVD2-Baseline: true")
		gittest.AddEmptyCommit(t, dir, "something else")
		gittest.AddEmptyCommit(t, dir, "chore: second baseline\n\nGLVD2-Baseline: true")
		want := gittest.AddEmptyCommit(t, dir, "chore: third baseline\n\nGLVD2-Baseline: true")
		gittest.AddEmptyCommit(t, dir, "and more stuff\n\nblub\nGLVD2-IMPORTANT: true")
		gittest.AddEmptyCommit(t, dir, "data(assessments): update") // should not match, since the trailer is not used

		sha, err := git.FindCommitByMessageAnchor(t.Context(), dir, anchor)
		require.NoError(t, err)
		assert.Equal(t, want, sha)
	})
}

// TestDiffFilesSince exercises path filtering and the no-changes case.
func TestDiffFilesSince(t *testing.T) {
	t.Parallel()

	t.Run("no changes returns nil", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		sha := gittest.AddEmptyCommit(t, dir, "chore: init")

		files, err := git.DiffFilesSince(t.Context(), dir, sha, "foo")
		require.NoError(t, err)
		assert.Nil(t, files)
	})

	t.Run("changed file is returned", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		shaA := gittest.AddEmptyCommit(t, dir, "chore: init")

		gittest.WriteFile(t, dir, "foo/a.txt", "hello")
		gittest.StageAllAndCommit(t, dir, "feat: add file")

		files, err := git.DiffFilesSince(t.Context(), dir, shaA, "foo")
		require.NoError(t, err)
		assert.Contains(t, files, "foo/a.txt")
	})

	t.Run("prefix includes only matching paths", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		shaA := gittest.AddEmptyCommit(t, dir, "chore: init")

		gittest.WriteFile(t, dir, "foo/a.txt", "hello")
		gittest.WriteFile(t, dir, "bar/b.txt", "world")
		gittest.StageAllAndCommit(t, dir, "feat: add files")

		files, err := git.DiffFilesSince(t.Context(), dir, shaA, "foo")
		require.NoError(t, err)
		assert.Contains(t, files, "foo/a.txt")
		assert.NotContains(t, files, "bar/b.txt")
	})

	t.Run("prefix excluding all existing paths returns nil", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		shaA := gittest.AddEmptyCommit(t, dir, "chore: init")

		gittest.WriteFile(t, dir, "foo/a.txt", "hello")
		gittest.WriteFile(t, dir, "bar/b.txt", "world")
		gittest.StageAllAndCommit(t, dir, "feat: add files")

		files, err := git.DiffFilesSince(t.Context(), dir, shaA, "baz")
		require.NoError(t, err)
		assert.Nil(t, files)
	})

	t.Run("uncommitted change appears in diff", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		gittest.WriteFile(t, dir, "foo/a.txt", "original")
		shaA := gittest.StageAllAndCommit(t, dir, "feat: add file")

		// Modify a tracked file without committing.
		gittest.WriteFile(t, dir, "foo/a.txt", "uncommitted")

		files, err := git.DiffFilesSince(t.Context(), dir, shaA, "foo")
		require.NoError(t, err)
		assert.Contains(t, files, "foo/a.txt")
	})

	t.Run("staged but uncommitted change appears in diff", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		gittest.WriteFile(t, dir, "foo/a.txt", "original")
		shaA := gittest.StageAllAndCommit(t, dir, "feat: add file")

		// Stage without committing.
		gittest.WriteFile(t, dir, "foo/a.txt", "staged")
		gittest.Run(t, dir, "add", "foo/a.txt")

		files, err := git.DiffFilesSince(t.Context(), dir, shaA, "foo")
		require.NoError(t, err)
		assert.Contains(t, files, "foo/a.txt")
	})

	t.Run("untracked file appears in diff", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		shaA := gittest.AddEmptyCommit(t, dir, "chore: init")

		// Never committed or staged.
		gittest.WriteFile(t, dir, "foo/a.txt", "untracked")

		files, err := git.DiffFilesSince(t.Context(), dir, shaA, "foo")
		require.NoError(t, err)
		assert.Contains(t, files, "foo/a.txt")
	})

	t.Run("deleted file appears in diff", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		gittest.WriteFile(t, dir, "foo/del.txt", "to be deleted")
		shaA := gittest.StageAllAndCommit(t, dir, "feat: add file")

		// Delete the file and commit - stageAllAndCommit uses git add -A which stages deletions.
		gittest.Run(t, dir, "rm", "foo/del.txt")
		gittest.StageAllAndCommit(t, dir, "chore: delete file")

		files, err := git.DiffFilesSince(t.Context(), dir, shaA, "foo")
		require.NoError(t, err)
		assert.Contains(t, files, "foo/del.txt")
	})

	t.Run("nonexistent valid SHA returns error", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		gittest.AddEmptyCommit(t, dir, "chore: init")

		_, err := git.DiffFilesSince(t.Context(), dir, "abcdef1", "foo")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "listing files changed since")
	})
}

// TestShowFileAtCommit exercises the ls-tree-based existence check,
// content retrieval, and the nonexistent SHA error path.
func TestShowFileAtCommit(t *testing.T) {
	t.Parallel()

	t.Run("file exists returns content", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		gittest.WriteFile(t, dir, "data/entry.json", `{"id":"CVE-2024-1"}`)
		sha := gittest.StageAllAndCommit(t, dir, "feat: add entry")

		content, err := git.ShowFileAtCommit(t.Context(), dir, sha, "data/entry.json")
		require.NoError(t, err)
		require.NotNil(t, content)
		assert.JSONEq(t, `{"id":"CVE-2024-1"}`, string(content))
	})

	t.Run("file absent at commit returns (nil, nil)", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		sha := gittest.AddEmptyCommit(t, dir, "chore: init")

		// Add the file in a later commit - it must not exist at sha.
		gittest.WriteFile(t, dir, "data/entry.json", "later")
		gittest.StageAllAndCommit(t, dir, "feat: add entry later")

		content, err := git.ShowFileAtCommit(t.Context(), dir, sha, "data/entry.json")
		require.NoError(t, err)
		assert.Nil(t, content)
	})

	t.Run("file modified later returns original content at SHA", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		gittest.WriteFile(t, dir, "data/entry.json", "original")
		sha := gittest.StageAllAndCommit(t, dir, "feat: add entry")

		gittest.WriteFile(t, dir, "data/entry.json", "modified")
		gittest.StageAllAndCommit(t, dir, "fix: update entry")

		content, err := git.ShowFileAtCommit(t.Context(), dir, sha, "data/entry.json")
		require.NoError(t, err)
		assert.Equal(t, "original", string(content))
	})

	t.Run("file deleted later returns original content at SHA", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		gittest.WriteFile(t, dir, "data/entry.json", "original")
		sha := gittest.StageAllAndCommit(t, dir, "feat: add entry")

		gittest.Run(t, dir, "rm", "data/entry.json")
		gittest.StageAllAndCommit(t, dir, "chore: delete entry")

		content, err := git.ShowFileAtCommit(t.Context(), dir, sha, "data/entry.json")
		require.NoError(t, err)
		assert.Equal(t, "original", string(content))
	})

	t.Run("nonexistent valid SHA returns error", func(t *testing.T) {
		t.Parallel()

		dir := gittest.InitRepo(t)
		gittest.AddEmptyCommit(t, dir, "chore: init")

		_, err := git.ShowFileAtCommit(t.Context(), dir, "abcdef1", "data/entry.json")
		require.Error(t, err)
	})
}
