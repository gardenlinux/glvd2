package presentation

type cveLandingData struct {
	commonData

	Total       int
	Relevant    int
	NotRelevant int
	Undecided   int
}

func (rr *renderRun) writeCVELanding() error {
	c := rr.agg.counts
	data := cveLandingData{
		commonData: commonData{
			Title:       "Find a CVE",
			Section:     cvesSection,
			Breadcrumbs: []breadcrumb{{Label: cvesLabel, URL: rr.r.urls.CVEs()}},
		},
		Total:       c.Total,
		Relevant:    c.Relevant,
		NotRelevant: c.NotRelevant,
		Undecided:   c.Undecided,
	}

	return rr.writePage(rr.r.urls.CVEs(), cvesSection, &data)
}
