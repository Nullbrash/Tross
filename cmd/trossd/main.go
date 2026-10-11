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
	"tross/internal/logring"
)

// version подставляется при сборке: -ldflags "-X main.version=…".
var version = "dev"

func main() { os.Exit(run()) }

func run() int {
	configPath := flag.String("config", "/etc/tross/config.yaml", "path to config file")
	dryRun := flag.Bool("dry-run", false, "force dry-run mode: change nothing in the system")
	dataDir := flag.String("data-dir", "", "override daemon.data_dir from the config")
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
	if *dataDir != "" {
		cfg.Daemon.DataDir = *dataDir
	}

	logs := logring.New(cfg.Log.RingSize)
	log, err := newLogger(os.Stderr, cfg.Log, logs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trossd:", err)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := daemon.Run(ctx, daemon.Options{Config: cfg, Log: log, Logs: logs, Version: version}); err != nil {
		log.Error("trossd failed", "err", err)
		return 1
	}
	return 0
}

func newLogger(w io.Writer, c config.Log, ring *logring.Ring) (*slog.Logger, error) {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(c.Level)); err != nil {
		return nil, err
	}
	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler = slog.NewTextHandler(w, opts)
	if c.Format == "json" {
		h = slog.NewJSONHandler(w, opts)
	}
	return slog.New(ring.Wrap(h)), nil
}
