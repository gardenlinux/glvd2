package assessment

import (
	"github.com/gardenlinux/glvd2/internal/model/cve_v5"
)

// RecordFromCVEV5 converts a CVEListV5 record into an incoming assessment [Record]
// suitable for merging. It populates the Upstream fields from the CVE data.
//
// TODO: Extract CVSS scores, CWEs, and references from the CVE containers.
// TODO: Populate Screening from matching logic.
func RecordFromCVEV5(cve *cve_v5.CVEV5) Record {
	a := Record{
		ID: cve.Metadata.ID,
		Upstream: UpstreamData{
			Description: firstEnglishDescriptionWithFallback(cve),
			PublishedAt: cve.Metadata.DatePublished,
		},
	}

	return a
}

// firstEnglishDescriptionWithFallback returns the first English-language description from the CNA container.
func firstEnglishDescriptionWithFallback(cve *cve_v5.CVEV5) string {
	for _, d := range cve.Containers.CNAContainer.Descriptions {
		if d.Lang == "en" || d.Lang == "en-US" {
			return d.Value
		}
	}

	// Fall back to first description regardless of language.
	if len(cve.Containers.CNAContainer.Descriptions) > 0 {
		return cve.Containers.CNAContainer.Descriptions[0].Value
	}

	return ""
}
