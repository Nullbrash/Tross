// Команда trossd — демон домашнего мульти-WAN балансира Tross.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"tross/internal/config"
	"tross/internal/daemon"
)

// version подставляется при сборке: -ldflags "-X main.version=…".
var version = "dev"

func main() { os.Exit(run()) }

func run() int {
	configPath := flag.String("config", "/etc/tross/config.yaml", "path to config file")
	dryRun := flag.Bool("dry-run", false, "force dry-run mode: change nothing in the system")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return 0
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trossd: config:", err)
		return 2
	}
	if *dryRun {
		cfg.Daemon.DryRun = true
	}

	log, err := newLogger(os.Stderr, cfg.Log)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trossd:", err)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := daemon.Run(ctx, daemon.Options{Config: cfg, Log: log, Version: version}); err != nil {
		log.Error("trossd failed", "err", err)
		return 1
	}
	return 0
}

func newLogger(w io.Writer, c config.Log) (*slog.Logger, error) {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(c.Level)); err != nil {
		return nil, err
	}
	opts := &slog.HandlerOptions{Level: lvl}
	if c.Format == "json" {
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	}
	return slog.New(slog.NewTextHandler(w, opts)), nil
}
