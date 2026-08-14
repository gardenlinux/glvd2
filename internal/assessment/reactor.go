package assessment

import "context"

// Reactor processes changes to CVE assessment records by producing side effects.
// Reactors run sequentially after diff is computed for each record.
// A reactor may modify the new assessment (e.g. storing an issue number) and
// produce side effects like creating GitHub issues or logging.
//
// old is passed by value (read-only snapshot of the baseline state).
// updated is passed by pointer and may be mutated by the reactor, but only for
// preserve-strategy fields (Meta, Manual) - never for overwrite/ingestion-owned
// fields, as the ChangeSet is not recomputed between reactors.
// cs contains the field-level diff (old -> updated) as a human-readable string
// snapshot and serves as an easy overview of what changed.
type Reactor interface {
	React(ctx context.Context, old Record, updated *Record, cs ChangeSet) error
}
