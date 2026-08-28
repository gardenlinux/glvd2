package main

import (
	"fmt"

	"github.com/gardenlinux/glvd2/internal/config"
	"github.com/gardenlinux/glvd2/internal/publish"
)

// commitGroupName enumerates the commit groups for the artifacts we store inside the
// repository.
type commitGroupName string

const (
	commitGroupCVEList       commitGroupName = "submodule-cvelistv5"
	commitGroupDebSecTracker commitGroupName = "submodule-debian-security-tracker"
	commitGroupAssessments   commitGroupName = "assessments"
	commitGroupAudit         commitGroupName = "audit"
)

// createCommitGroups returns the commit groups for the artifacts, we store inside
// the repository like the assessments or audit files.
// Commit messages are not set here; they are supplied at publish time via commitMessageForGroup.
func createCommitGroups(cfg *config.AppConfig) []publish.CommitGroup {
	return []publish.CommitGroup{
		{Name: string(commitGroupCVEList), Paths: []string{cfg.CVEListV5SubRepoPath}},
		{Name: string(commitGroupDebSecTracker), Paths: []string{cfg.DebSecTrackerSubRepoPath}},
		{Name: string(commitGroupAssessments), Paths: []string{cfg.AssessmentsDir}},
		{Name: string(commitGroupAudit), Paths: []string{cfg.AuditDir}},
	}
}

// commitMessageForGroup builds the commit message for a commit group by its name,
// using post-run summary counts where relevant.
func commitMessageForGroup(name string, cfg *config.AppConfig, summary runSummary) string {
	switch commitGroupName(name) {
	case commitGroupCVEList:
		return buildSubmoduleUpdateMessage("cvelistv5")
	case commitGroupDebSecTracker:
		return buildSubmoduleUpdateMessage("debsectracker")
	case commitGroupAssessments:
		return buildAssessmentsUpdateMessage(
			summary.Created,
			summary.Updated,
			summary.Unchanged,
			cfg.BaselineCommitAnchor,
		)
	case commitGroupAudit:
		return buildAuditUpdateMessage([]string{"mapping_result.json", "package_index.json"})
	default:
		panic(fmt.Sprintf("no commit message builder for group %q", name))
	}
}
