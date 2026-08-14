package reactor

import (
	"context"
	"log/slog"

	"github.com/gardenlinux/glvd2/internal/assessment"
)

// Log is a reactor that emits structured log entries when a CVE assessment record changes.
type Log struct {
	Logger *slog.Logger
}

// React logs the change type and field-level diffs for a CVE assessment record.
func (l Log) React(
	ctx context.Context,
	_ assessment.Record,
	updated *assessment.Record,
	cs assessment.ChangeSet,
) error {
	if !cs.HasChanges() {
		return nil
	}

	logger := l.Logger
	if logger == nil {
		logger = slog.Default()
	}

	attrs := []slog.Attr{
		slog.String("cve_id", cs.CVEID),
		slog.String("change_type", cs.Type.String()),
		slog.Int("field_changes", len(cs.Changes)),
	}

	if updated.GetGlobalStatus() != "" {
		attrs = append(attrs, slog.String("global_status", string(updated.GetGlobalStatus())))
	}

	changeAttrs := make([]slog.Attr, 0, len(cs.Changes))
	for _, fc := range cs.Changes {
		changeAttrs = append(changeAttrs, slog.Group(fc.Field.String(),
			slog.String("old", fc.OldValue),
			slog.String("new", fc.NewValue),
		))
	}

	attrs = append(attrs, slog.Attr{
		Key:   "changes",
		Value: slog.GroupValue(changeAttrs...),
	})

	logger.LogAttrs(ctx, slog.LevelInfo, "cve assessment record changed", attrs...)

	return nil
}
