package presentation

import (
	"context"
	"time"
)

type cveEntry struct {
	ID string
	// FirstSeenAt is when we first tracked the record.
	// For an undecided CVE it is effectively the date it has been pending a decision since.
	FirstSeenAt time.Time
	// PublishedAt is the CVE's upstream publication date.
	PublishedAt time.Time
}

type undecidedRow struct {
	ID             string
	URL            string
	UndecidedSince string
	Published      string
}

type undecidedData struct {
	commonData

	CVEs []undecidedRow
}

func (rr *renderRun) writeUndecidedList(ctx context.Context) error {
	const (
		path  = "cves/undecided/index.html"
		title = "Relevance undecided"
	)
	data := undecidedData{
		commonData: commonData{
			Title:   title,
			Section: cvesSection,
			Breadcrumbs: []breadcrumb{
				{Label: cvesLabel, URL: rr.r.urls.CVEs()},
				{Label: title, URL: path},
			},
		},
	}

	for _, entry := range rr.agg.undecided {
		if err := ctx.Err(); err != nil {
			return err
		}

		url, err := rr.r.urls.CVE(entry.ID)
		if err != nil {
			return err
		}

		data.CVEs = append(data.CVEs, undecidedRow{
			ID:             entry.ID,
			URL:            url,
			UndecidedSince: formatDate(entry.FirstSeenAt),
			Published:      formatDate(entry.PublishedAt),
		})
	}

	return rr.writePage(path, "undecided", &data)
}
