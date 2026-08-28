// Package publish commits and pushes generated artifact groups to the repository.
package publish

// CommitGroup is a set of repository paths committed together as one commit.
// A commit group must own its paths exclusively, so its path-scoped commit
// contains only that group's state. The commit message is supplied at
// [Service.Run] time, since it may depend on post-run state.
type CommitGroup struct {
	Name  string   // identifies the commit group for logging (e.g. "assessments")
	Paths []string // owned folders, which are staged and committed together
}
