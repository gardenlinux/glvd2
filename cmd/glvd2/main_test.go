package main

import (
	"testing"
)

// func TestSomething(t *testing.T) {
// 	logger := slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{
// 		Level: slog.LevelDebug,
// 	}))

// 	// use logger directly, or set as default
// 	slog.SetDefault(logger)
// }

type testWriter struct{ t *testing.T }

func (w testWriter) Write(b []byte) (int, error) {
	w.t.Log(string(b))
	return len(b), nil
}
