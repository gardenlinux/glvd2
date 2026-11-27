package presentation

type statisticsData struct {
	commonData

	ManualOverrides int
	AutoReasons     []countRow
	LifecycleStates []countRow
}

func (rr *renderRun) writeStatisticsPage() error {
	c := rr.agg.counts

	data := statisticsData{
		commonData: commonData{
			Title:       "Statistics",
			Section:     "statistics",
			Breadcrumbs: []breadcrumb{{Label: "Statistics", URL: rr.r.urls.Statistics()}},
		},
		ManualOverrides: c.ManualOverrides,
		AutoReasons:     c.autoReasonRows(),
		LifecycleStates: c.lifecycleRows(),
	}

	return rr.writePage(rr.r.urls.Statistics(), "statistics", &data)
}
