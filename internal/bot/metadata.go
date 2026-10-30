package bot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/gardenlinux/glvd2/internal/assessment"
	gogithub "github.com/google/go-github/v72/github"
)

var cveIDRegex = regexp.MustCompile(`^CVE-(\d{4})-(\d+)$`)

func IsValidCVEID(id string) bool {
	return cveIDRegex.MatchString(id)
}

// ErrAssessmentNotFound is returned when no assessment file exists for the CVE yet.
var ErrAssessmentNotFound = errors.New("assessment file not found")

// AssessmentRepoService reads and writes assessment.Record files in a GitHub repo.
type AssessmentRepoService struct {
	gh        *gogithub.Client
	repoOwner string
	repoName  string
}

func NewAssessmentRepoService(gh *gogithub.Client, repoOwner, repoName string) *AssessmentRepoService {
	return &AssessmentRepoService{gh: gh, repoOwner: repoOwner, repoName: repoName}
}

// ReadAssessment fetches and parses the assessment file for cveID.
// Returns ErrAssessmentNotFound if the file does not exist yet.
func (s *AssessmentRepoService) ReadAssessment(ctx context.Context, cveID string) (*assessment.Record, string, error) {
	path, err := assessmentRepoPath(cveID)
	if err != nil {
		return nil, "", err
	}

	file, _, _, err := s.gh.Repositories.GetContents(ctx, s.repoOwner, s.repoName, path,
		&gogithub.RepositoryContentGetOptions{})
	if err != nil {
		return nil, "", ErrAssessmentNotFound
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
	path, err := assessmentRepoPath(rec.ID)
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
		Message: gogithub.Ptr(commitMsg),
		Content: data,
	}
	if sha != "" {
		opts.SHA = gogithub.Ptr(sha)
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

// assessmentRepoPath returns the in-repo file path for a CVE, e.g. data/2024/1xxx/CVE-2024-1234.json.
func assessmentRepoPath(cveID string) (string, error) {
	matches := cveIDRegex.FindStringSubmatch(cveID)
	if matches == nil {
		return "", errors.New("invalid CVE ID: " + cveID)
	}
	year := matches[1]
	number := matches[2]

	bucketLen := max(len(number)-3, 1) //nolint:mnd // 3 = digits replaced with "xxx"
	bucket := number[:bucketLen] + "xxx"

	return fmt.Sprintf("data/%s/%s/%s.json", year, bucket, cveID), nil
}

// IsTeamMember reports whether actor is an active member of teamSlug in the given org.
func IsTeamMember(ctx context.Context, gh *gogithub.Client, org, teamSlug, actor string) (bool, error) {
	membership, _, err := gh.Teams.GetTeamMembershipBySlug(ctx, org, teamSlug, actor)
	if err != nil {
		return false, nil //nolint:nilerr // 404 means not a member
	}
	return strings.EqualFold(membership.GetState(), "active"), nil
}
