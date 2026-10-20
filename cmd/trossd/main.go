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
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "debug":
			return runDebug(os.Args[2:])
		case "passwd":
			return runPasswd(os.Args[2:])
		case "ca":
			return runCA(os.Args[2:])
		}
	}
	configPath := flag.String("config", "/etc/tross/config.yaml", "path to config file")
	dryRun := flag.Bool("dry-run", false, "force dry-run mode: change nothing in the system")
	dataDir := flag.String("data-dir", "", "override daemon.data_dir from the config")
	cleanup := flag.Bool("cleanup", false, "remove rules left by a crashed daemon (NAT stays) and exit; for ExecStopPost")
	purge := flag.Bool("purge", false, "remove all daemon rules including NAT and exit; for uninstalling")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return 0
	}

	// SIGHUP — как остановка: без обработчика процесс умер бы, не сняв правила.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trossd: config:", err)
		if *cleanup || *purge {
			return cleanupWithoutConfig(ctx, *purge)
		}
		return 2
	}
	cfg.ApplyFlags(*dryRun, *dataDir)

	logs := logring.New(cfg.Log.RingSize)
	log, err := newLogger(os.Stderr, cfg.Log, logs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trossd:", err)
		return 2
	}

	if *cleanup || *purge {
		if err := daemon.Cleanup(ctx, cfg, log, *purge); err != nil {
			log.Error("trossd cleanup failed", "err", err)
			return 1
		}
		log.Info("trossd cleanup done", "purge", *purge)
		return 0
	}

	if err := daemon.Run(ctx, daemon.Options{Config: cfg, Log: log, Logs: logs, Version: version, ConfigPath: *configPath}); err != nil {
		log.Error("trossd failed", "err", err)
		return 1
	}
	return 0
}

// cleanupWithoutConfig — очистка после аварии, когда конфиг уже не читается:
// снимается то, что конфига не требует; код возврата всё равно ошибочный.
func cleanupWithoutConfig(ctx context.Context, purge bool) int {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := daemon.CleanupWithoutConfig(ctx, log, purge); err != nil {
		log.Error("trossd cleanup without config failed", "err", err)
	} else {
		log.Warn("trossd cleanup without config: policy rules removed, routes in link tables left")
	}
	return 1
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
