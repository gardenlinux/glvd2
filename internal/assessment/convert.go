package assessment

import (
	"time"

	"github.com/gardenlinux/glvd2/internal/model/cve_v5"
)

// RecordFromCVEV5 converts a CVEListV5 record into an incoming assessment [Record]
// suitable for merging. It populates the Upstream fields from the CVE data and
// seeds Meta.FirstSeenAt to the current time.
//
// FirstSeenAt is set here on every incoming record. For a new CVE,
// mergeRecords returns the incoming record's FirstSeenAt value and the time is set.
// On subsequent runs the preserve mechanism of the field keeps the original value.
func RecordFromCVEV5(cve *cve_v5.CVEV5) Record {
	a := Record{
		ID: cve.Metadata.ID,
		Upstream: UpstreamData{
			Description: firstEnglishDescriptionWithFallback(cve),
			PublishedAt: cve.Metadata.DatePublished,
			State:       cveStateFromV5(cve.Metadata.State),
		},
		Meta: Metadata{
			FirstSeenAt: time.Now().UTC(),
		},
	}

	return a
}

// cveStateFromV5 maps a cve_v5.StateType to the domain-local CVEState.
func cveStateFromV5(s cve_v5.StateType) CVEState {
	switch s {
	case cve_v5.StateRejected:
		return CVEStateRejected
	case cve_v5.StatePublished:
		return CVEStatePublished
	}
	return CVEStatePublished
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
