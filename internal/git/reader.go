package git

import "context"

// Reader provides read-only access to a git repository's history.
// It implements the GitReader interface expected by cvedata.NewBaseline.
type Reader struct {
	dir string
}

// NewReader creates a Reader that executes git commands against the given directory.
func NewReader(dir string) *Reader {
	return &Reader{dir: dir}
}

// FindCommitByMessageAnchor returns the SHA of the most recent commit whose message
// contains a line matching anchor. Returns empty string if no matching commit is found.
func (r *Reader) FindCommitByMessageAnchor(ctx context.Context, anchor string) (string, error) {
	return FindCommitByMessageAnchor(ctx, r.dir, anchor)
}

// DiffFilesSince returns file paths changed between commitSHA and HEAD
// within the given path prefix. Returns nil if no files were modified.
func (r *Reader) DiffFilesSince(ctx context.Context, commitSHA, pathPrefix string) ([]string, error) {
	return DiffFilesSince(ctx, r.dir, commitSHA, pathPrefix)
}

// ShowFileAtCommit returns the content of a file at a specific commit.
// Returns nil, nil if the file did not exist at that commit.
func (r *Reader) ShowFileAtCommit(ctx context.Context, commitSHA, filePath string) ([]byte, error) {
	return ShowFileAtCommit(ctx, r.dir, commitSHA, filePath)
}
