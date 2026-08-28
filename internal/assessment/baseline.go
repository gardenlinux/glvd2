package assessment

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/gardenlinux/glvd2/internal/config"
)

// GitReader abstracts git operations needed by the baseline mechanism.
type GitReader interface {
	// FindCommitByMessageAnchor returns the SHA of the most recent commit whose
	// message contains a line matching anchor. Returns empty string if no match is found.
	FindCommitByMessageAnchor(ctx context.Context, anchor string) (string, error)

	// DiffFilesSince returns file paths that differ from commitSHA within the given path prefix,
	// covering tracked changes and untracked files. Returns nil if none differ.
	DiffFilesSince(ctx context.Context, commitSHA, pathPrefix string) ([]string, error)

	// ShowFileAtCommit returns the content of a file at a specific commit.
	// Returns nil, nil if the file did not exist at that commit.
	ShowFileAtCommit(ctx context.Context, commitSHA, filePath string) ([]byte, error)
}

// Baseline provides access to the state of assessment records from the last program run.
type Baseline struct {
	git            GitReader
	commitSHA      string // empty if no previous baseline commit exists (first run)
	assessmentsDir string // relative path to assessments (default: data/assessments)
}

// NewBaseline resolves the last baseline commit and returns a [Baseline].
// If no previous baseline commit exists (first run), returns a Baseline that always yields empty records.
func NewBaseline(ctx context.Context, gitReader GitReader, cfg *config.AppConfig) (*Baseline, error) {
	sha, err := gitReader.FindCommitByMessageAnchor(ctx, cfg.BaselineCommitAnchor)
	if err != nil {
		return nil, fmt.Errorf("finding last baseline commit by anchor: %w", err)
	}

	if sha == "" {
		slog.Info("no previous baseline commit found, treating as first run")
	} else {
		slog.Info("baseline resolved", slog.String("commit", sha))
	}

	return &Baseline{
		git:            gitReader,
		commitSHA:      sha,
		assessmentsDir: cfg.AssessmentsDir,
	}, nil
}

// IsFirstRun returns true if no previous baseline commit was found.
func (b *Baseline) IsFirstRun() bool {
	return b.commitSHA == ""
}

// CommitSHA returns the resolved baseline commit SHA (empty if first run).
func (b *Baseline) CommitSHA() string {
	return b.commitSHA
}

// ExternallyModifiedFiles returns the list of CVE assessment record paths modified since the last baseline commit.
// These are files that an external actor changed like our Github bot.
// Returns nil if this is the first run.
func (b *Baseline) ExternallyModifiedFiles(ctx context.Context) ([]string, error) {
	if b.commitSHA == "" {
		return nil, nil
	}

	files, err := b.git.DiffFilesSince(ctx, b.commitSHA, b.assessmentsDir)
	if err != nil {
		return nil, fmt.Errorf("listing bot-modified files: %w", err)
	}

	return files, nil
}

// LoadAssessmentRecord loads the assessment record at the given CVE ID as it was at the last baseline commit.
// Returns an empty asessment [Record] (zero ID), if the file didn't exist at that commit or if there is no
// baseline commit yet.
func (b *Baseline) LoadAssessmentRecord(ctx context.Context, cveID string) (Record, error) {
	if b.commitSHA == "" {
		return Record{}, nil
	}

	relPath, err := Path(b.assessmentsDir, cveID)
	if err != nil {
		return Record{}, err
	}

	content, err := b.git.ShowFileAtCommit(ctx, b.commitSHA, relPath)
	if err != nil {
		return Record{}, fmt.Errorf("loading baseline assessment record for %s: %w", cveID, err)
	}

	if content == nil {
		// File didn't exist at that commit.
		return Record{}, nil
	}

	var a Record
	if unmarshalErr := json.Unmarshal(content, &a); unmarshalErr != nil {
		return Record{}, fmt.Errorf("parsing baseline assessment record for %s: %w", cveID, unmarshalErr)
	}

	return a, nil
}
