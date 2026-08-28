package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildAssessmentsUpdateMessage(t *testing.T) {
	t.Parallel()

	const anchor = "GLVD2-Baseline: true"
	msg := buildAssessmentsUpdateMessage(42, 2, 10, anchor)

	want := "data(assessments): update\n\n" +
		"created: 42\n" +
		"updated: 2\n" +
		"unchanged: 10\n\n" +
		"GLVD2-Baseline: true\n"
	assert.Equal(t, want, msg)
}

func TestBuildAuditUpdateMessage(t *testing.T) {
	t.Parallel()

	msg := buildAuditUpdateMessage([]string{"mapping_result.json", "package_index.json"})

	want := "data(audit): update\n\n" +
		"recorded artifacts:\n" +
		"- mapping_result.json\n" +
		"- package_index.json\n"
	assert.Equal(t, want, msg)
}

func TestBuildSubmoduleUpdateMessage(t *testing.T) {
	t.Parallel()

	msg := buildSubmoduleUpdateMessage("cvelistv5")

	assert.Equal(t, "data(cvelistv5): update\n", msg)
}
