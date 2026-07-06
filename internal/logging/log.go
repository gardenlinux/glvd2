package logging

import (
	"context"
	"log/slog"
)

const (
	LevelTrace = slog.Level(-8) // below LevelDebug (-4)
)

func Trace(logger *slog.Logger, msg string, args ...any) {
	logger.Log(context.Background(), LevelTrace, msg, args...)
}
