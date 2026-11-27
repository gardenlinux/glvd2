package presentation

import (
	"slices"
	"strings"

	"github.com/gardenlinux/glvd2/internal/assessment"
)

// databaseCounts summarizes CVE relevance and the underlying triage statistics.
type databaseCounts struct {
	Total           int
	Relevant        int
	NotRelevant     int
	Undecided       int
	ManualOverrides int
	AutoReasons     map[assessment.TriageReason]int
	LifecycleStates map[assessment.CVEState]int
}

func newDatabaseCounts() databaseCounts {
	return databaseCounts{
		AutoReasons:     make(map[assessment.TriageReason]int),
		LifecycleStates: make(map[assessment.CVEState]int),
	}
}

// add folds one record into the counts.
func (c *databaseCounts) add(rec assessment.Record) {
	c.Total++

	switch rec.GetGlobalStatus() {
	case assessment.StatusRelevant:
		c.Relevant++
	case assessment.StatusNotRelevant:
		c.NotRelevant++
	case assessment.StatusUndecided:
		c.Undecided++
	}

	if reason := rec.Screening.AutoTriage.Reason; reason != "" {
		c.AutoReasons[reason]++
	}

	if !rec.Manual.ManualTriage.IsEmpty() {
		c.ManualOverrides++
	}

	if state := rec.Upstream.State; state != "" {
		c.LifecycleStates[state]++
	}
}

// countRow is one label/count pair for the statistics page.
type countRow struct {
	Label string
	Count int
}

// autoReasonRows returns the automated-reason counts, ordered by label.
func (c *databaseCounts) autoReasonRows() []countRow {
	rows := make([]countRow, 0, len(c.AutoReasons))
	for reason, count := range c.AutoReasons {
		rows = append(rows, countRow{Label: string(reason), Count: count})
	}
	slices.SortFunc(rows, func(a, b countRow) int {
		return strings.Compare(a.Label, b.Label)
	})

	return rows
}

// lifecycleRows returns the upstream lifecycle-state counts, ordered by label.
func (c *databaseCounts) lifecycleRows() []countRow {
	rows := make([]countRow, 0, len(c.LifecycleStates))
	for state, count := range c.LifecycleStates {
		rows = append(rows, countRow{Label: string(state), Count: count})
	}
	slices.SortFunc(rows, func(a, b countRow) int {
		return strings.Compare(a.Label, b.Label)
	})

	return rows
}
