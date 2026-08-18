package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/gardenlinux/glvd2/internal/config"
	_ "modernc.org/sqlite"
)

// Exit code for interrupt (SIGINT): 128 + 2.
const exitInterrupted = 130

func main() {
	cfg, err := config.LoadAppConfig("./config")
	if err != nil {
		slog.Error("Could not read the config file", slog.Any("error", err))
		return
	}

	root := newRootCmd(cfg)
	registerSubcommands(root, cfg)

	// stop() must be called explicitly: os.Exit skips deferred calls.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	// Force-exit on second SIGINT or SIGTERM signal.
	hardExit := make(chan os.Signal, 1)
	signal.Notify(hardExit, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ctx.Done() // first signal
		<-hardExit   // second signal
		slog.Warn("second interrupt received, forcing exit")
		os.Exit(exitInterrupted)
	}()

	err = root.ExecuteContext(ctx)
	stop() // defer not possible (os.exit)
	switch {
	case err == nil:
		// normal exit
	case errors.Is(err, context.Canceled):
		slog.Info("interrupted, shutting down")
		os.Exit(exitInterrupted)
	default:
		slog.Error(err.Error())
		os.Exit(1)
	}
}
