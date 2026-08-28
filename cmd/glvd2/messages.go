package main

import (
	"fmt"
	"strings"
)

func buildAssessmentsUpdateMessage(created, updated, unchanged int, anchor string) string {
	return fmt.Sprintf(
		"data(assessments): update\n\n"+
			"created: %d\n"+
			"updated: %d\n"+
			"unchanged: %d\n\n"+
			"%s\n",
		created, updated, unchanged, anchor,
	)
}

func buildAuditUpdateMessage(artifacts []string) string {
	var b strings.Builder
	const estimatedSize = 256
	b.Grow(estimatedSize)
	b.WriteString("data(audit): update\n\nrecorded artifacts:\n")
	for _, a := range artifacts {
		b.WriteString("- ")
		b.WriteString(a)
		b.WriteByte('\n')
	}

	return b.String()
}

func buildSubmoduleUpdateMessage(scope string) string {
	return fmt.Sprintf("data(%s): update\n", scope)
}
