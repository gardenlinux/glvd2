package publish_test

import "github.com/gardenlinux/glvd2/internal/publish"

// Shared fixtures for the publish package tests. Used by both the fake-based unit
// tests in service_test.go and the real-git integration tests in integration_test.go.

func createCommitGroup() []publish.CommitGroup {
	return []publish.CommitGroup{
		{Name: "assessments", Paths: []string{"data/assessments"}},
		{Name: "audit", Paths: []string{"data/audit"}},
	}
}

func testMessageForCommitGroup(name string, _ bool) string {
	return "data(" + name + "): update"
}

// testMessageWithCompletionMarker is a message function that appends the completion
// marker to the last group's commit message, mirroring how the cmd layer attaches the trailer.
func testMessageWithCompletionMarker(name string, isLastCommit bool) string {
	message := "data(" + name + "): update"
	if isLastCommit {
		message += "\n\n" + testCompletionMarker + "\n"
	}

	return message
}
