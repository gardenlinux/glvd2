package bot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gardenlinux/glvd2/internal/assessment"
	gogithub "github.com/google/go-github/v72/github"
)

// IsValidCVEID reports whether id is a valid CVE identifier.
func IsValidCVEID(id string) bool {
	return assessment.ValidateCVEID(id) == nil
}

// ErrAssessmentNotFound is returned when no assessment file exists for the CVE yet.
var ErrAssessmentNotFound = errors.New("assessment file not found")

// AssessmentRepoService reads and writes assessment.Record files in a GitHub repo.
type AssessmentRepoService struct {
	gh        *gogithub.Client
	repoOwner string
	repoName  string
	baseDir   string
}

func NewAssessmentRepoService(gh *gogithub.Client, repoOwner, repoName, baseDir string) *AssessmentRepoService {
	if baseDir == "" {
		baseDir = "data/assessments"
	}
	return &AssessmentRepoService{gh: gh, repoOwner: repoOwner, repoName: repoName, baseDir: baseDir}
}

// ReadAssessment fetches and parses the assessment file for cveID.
// Returns ErrAssessmentNotFound if the file does not exist yet.
func (s *AssessmentRepoService) ReadAssessment(ctx context.Context, cveID string) (*assessment.Record, string, error) {
	path, err := assessment.Path(s.baseDir, cveID)
	if err != nil {
		return nil, "", err
	}

	file, _, resp, err := s.gh.Repositories.GetContents(ctx, s.repoOwner, s.repoName, path,
		&gogithub.RepositoryContentGetOptions{})
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return nil, "", ErrAssessmentNotFound
		}
		return nil, "", fmt.Errorf("could not fetch assessment for %s: %w", cveID, err)
	}

	content, err := file.GetContent()
	if err != nil {
		return nil, "", fmt.Errorf("could not decode assessment for %s: %w", cveID, err)
	}

	var rec assessment.Record
	if err = json.Unmarshal([]byte(content), &rec); err != nil {
		return nil, "", fmt.Errorf("could not parse assessment for %s: %w", cveID, err)
	}

	return &rec, file.GetSHA(), nil
}

// WriteAssessment creates or updates the assessment file for rec.
// sha must be the file's current SHA (from ReadAssessment), or empty when creating.
func (s *AssessmentRepoService) WriteAssessment(ctx context.Context, rec *assessment.Record, sha string) error {
	path, err := assessment.Path(s.baseDir, rec.ID)
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	commitMsg := "chore: update assessment for " + rec.ID
	opts := &gogithub.RepositoryContentFileOptions{
		Message: &commitMsg,
		Content: data,
	}
	if sha != "" {
		opts.SHA = &sha
		_, _, err = s.gh.Repositories.UpdateFile(ctx, s.repoOwner, s.repoName, path, opts)
	} else {
		_, _, err = s.gh.Repositories.CreateFile(ctx, s.repoOwner, s.repoName, path, opts)
	}
	if err != nil {
		return fmt.Errorf("could not write assessment for %s: %w", rec.ID, err)
	}

	return nil
}

// NewAssessmentRecord creates a minimal assessment.Record for a CVE seen for the first time.
func NewAssessmentRecord(cveID string, issueNumber int, now time.Time) *assessment.Record {
	return &assessment.Record{
		ID: cveID,
		Meta: assessment.Metadata{
			IssueNumber: issueNumber,
			FirstSeenAt: now,
		},
	}
}

// IsTeamMember reports whether actor is an active member of teamSlug in the given org.
// Returns false, nil when the actor is not a member (404); returns an error for any
// other API failure so callers can distinguish "not a member" from "could not check".
func IsTeamMember(ctx context.Context, gh *gogithub.Client, org, teamSlug, actor string) (bool, error) {
	membership, resp, err := gh.Teams.GetTeamMembershipBySlug(ctx, org, teamSlug, actor)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return false, nil
		}
		return false, fmt.Errorf("checking team membership for %s: %w", actor, err)
	}
	return strings.EqualFold(membership.GetState(), "active"), nil
}
