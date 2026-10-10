// Package daemon собирает модули демона вместе и управляет их жизненным циклом.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"tross/core/event"
	"tross/internal/api"
	"tross/internal/config"
	"tross/internal/dataplane"
	"tross/internal/linkmon"
	"tross/internal/store"
)

const shutdownTimeout = 5 * time.Second

type Options struct {
	Config  *config.Config
	Log     *slog.Logger
	Version string
}

// Run работает до отмены ctx (сигнал) или фатальной ошибки модуля.
// При любом исходе снимает правила dataplane.
func Run(ctx context.Context, opts Options) error {
	cfg, log := opts.Config, opts.Log
	log.Info("trossd starting", "version", opts.Version, "dry_run", cfg.Daemon.DryRun, "links", len(cfg.Links))

	bus := event.NewBus()
	// SQLite появится вместе с первыми данными, которые нужно хранить (этап 1+).
	st := store.NewMemory(cfg.Log.RingSize)
	defer st.Close()

	dp, err := newDataplane(cfg, log)
	if err != nil {
		return err
	}
	if err := dp.Setup(ctx, dataplaneSpec(cfg)); err != nil {
		return fmt.Errorf("dataplane setup: %w", err)
	}
	defer func() {
		// Контекст запуска уже отменён — снимаем правила с собственным таймаутом.
		tctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := dp.Teardown(tctx); err != nil {
			log.Error("dataplane teardown failed", "err", err)
		}
	}()

	if !cfg.Daemon.DryRun {
		return errors.New("real link monitor is not implemented yet (stage 1); run with dry_run")
	}
	mon := linkmon.NewFake(cfg.ModelLinks(), bus, cfg.Monitor.Interval, uint64(time.Now().UnixNano()))

	srv := &http.Server{
		Handler: api.New(api.Options{
			Log:             log,
			Monitor:         mon,
			AllowedNetworks: cfg.API.AllowedNetworks,
			Version:         opts.Version,
			DryRun:          cfg.Daemon.DryRun,
		}).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	// Слушаем до запуска фоновых задач: занятый порт — ошибка старта, а не фоновая.
	ln, err := net.Listen("tcp", cfg.API.Listen)
	if err != nil {
		return fmt.Errorf("api listen: %w", err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	fatal := make(chan error, 2)

	events, unsubscribe := bus.Subscribe(256)
	wg.Go(func() { logEvents(log, st, events) })
	wg.Go(func() {
		if err := mon.Run(runCtx); err != nil {
			fatal <- fmt.Errorf("link monitor: %w", err)
		}
	})
	wg.Go(func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fatal <- fmt.Errorf("api: %w", err)
		}
	})
	log.Info("api listening", "addr", ln.Addr().String())
	bus.Publish(event.Event{Topic: event.TopicDaemon, Data: "started"})

	var runErr error
	select {
	case <-ctx.Done():
		log.Info("shutdown requested")
	case runErr = <-fatal:
		log.Error("fatal error, shutting down", "err", runErr)
	}

	bus.Publish(event.Event{Topic: event.TopicDaemon, Data: "stopping"})
	sctx, scancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer scancel()
	if err := srv.Shutdown(sctx); err != nil {
		log.Warn("api shutdown", "err", err)
	}
	cancel()
	unsubscribe()
	wg.Wait()
	log.Info("trossd stopped")
	return runErr
}

func newDataplane(cfg *config.Config, log *slog.Logger) (dataplane.Dataplane, error) {
	if cfg.Daemon.DryRun {
		return dataplane.NewFake(log), nil
	}
	return dataplane.NewSystem(log)
}

func dataplaneSpec(cfg *config.Config) dataplane.Spec {
	spec := dataplane.Spec{
		LANInterface: cfg.LAN.Interface,
		LANNetworks:  append([]netip.Prefix(nil), cfg.LAN.Networks...),
	}
	for _, l := range cfg.Links {
		spec.Links = append(spec.Links, dataplane.LinkSpec{
			Link: l.Model(), Table: l.Table, FwMark: l.FwMark, Gateway: l.GatewayAddr(),
		})
	}
	return spec
}

// logEvents пишет события в лог и историю, пока канал не закрыт отпиской.
func logEvents(log *slog.Logger, st store.Store, events <-chan event.Event) {
	for e := range events {
		log.Info("event", "topic", e.Topic, "data", e.Data)
		if err := st.AppendEvent(context.Background(), e); err != nil {
			log.Warn("store event", "err", err)
		}
	}
}
