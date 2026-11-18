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

	msg := buildAuditUpdateMessage([]string{"deb_mapping_result.json", "deb_package_identifiers.json"})

	want := "data(audit): update\n\n" +
		"recorded artifacts:\n" +
		"- deb_mapping_result.json\n" +
		"- deb_package_identifiers.json\n"
	assert.Equal(t, want, msg)
}

func TestBuildSubmoduleUpdateMessage(t *testing.T) {
	t.Parallel()

	msg := buildSubmoduleUpdateMessage("cvelistv5")

	assert.Equal(t, "data(cvelistv5): update\n", msg)
}

func TestAppendTrailer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		message string
		line    string
		want    string
	}{
		{
			name:    "appends a blank-line-separated trailer",
			message: "data(audit): update\n",
			line:    "GLVD2-Last-Commit-Of-Run: true",
			want:    "data(audit): update\n\nGLVD2-Last-Commit-Of-Run: true\n",
		},
		{
			name:    "coexists with an existing trailer",
			message: "data(assessments): update\n\nGLVD2-Baseline: true\n",
			line:    "GLVD2-Last-Commit-Of-Run: true",
			want:    "data(assessments): update\n\nGLVD2-Baseline: true\n\nGLVD2-Last-Commit-Of-Run: true\n",
		},
		{
			name:    "empty line is a no-op",
			message: "data(audit): update\n",
			line:    "",
			want:    "data(audit): update\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, appendTrailer(tc.message, tc.line))
		})
	}
}
