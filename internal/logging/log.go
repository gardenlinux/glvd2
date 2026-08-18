package logging

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

const (
	LevelTrace = slog.Level(-8) // below LevelDebug (-4)
)

func Trace(logger *slog.Logger, msg string, args ...any) {
	logger.Log(context.Background(), LevelTrace, msg, args...)
}

// replaceAttr enables rendering of the custom "TRACE" log level label.
func replaceAttr(_ []string, a slog.Attr) slog.Attr {
	if a.Key == slog.LevelKey {
		level, ok := a.Value.Any().(slog.Level)
		if !ok {
			return a
		}
		if LevelTrace == level {
			a.Value = slog.StringValue("TRACE")
		}
	}
	return a
}

// Configure parses levelStr, installs a matching slog default handler, and
// returns an error if the level string is unrecognised (defaulting to debug).
func Configure(levelStr string) error {
	var logLevel slog.LevelVar
	var err error
	switch strings.ToLower(levelStr) {
	case "error":
		logLevel.Set(slog.LevelError)
	case "warn":
		logLevel.Set(slog.LevelWarn)
	case "info":
		logLevel.Set(slog.LevelInfo)
	case "debug":
		logLevel.Set(slog.LevelDebug)
	case "trace":
		logLevel.Set(LevelTrace)
	default:
		logLevel.Set(slog.LevelDebug)
		err = fmt.Errorf("unknown log level: %s", levelStr)
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level:       &logLevel,
		ReplaceAttr: replaceAttr,
	})))

	return err
}
