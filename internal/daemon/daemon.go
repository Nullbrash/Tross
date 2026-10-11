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
	"os"
	"path/filepath"
	"sync"
	"time"

	"tross/core/event"
	"tross/core/linkhealth"
	"tross/core/model"
	"tross/internal/api"
	"tross/internal/config"
	"tross/internal/dataplane"
	"tross/internal/linkmon"
	"tross/internal/logring"
	"tross/internal/store"
)

const (
	shutdownTimeout = 5 * time.Second
	collectEvery    = time.Minute
	dbFile          = "tross.db"
)

type Options struct {
	Config *config.Config
	Log    *slog.Logger
	// Logs — кольцо свежих записей того же журнала (для API); может быть nil.
	Logs    *logring.Ring
	Version string
}

// Run работает до отмены ctx (сигнал) или фатальной ошибки модуля.
// При любом исходе снимает правила dataplane.
func Run(ctx context.Context, opts Options) error {
	cfg, log := opts.Config, opts.Log
	log.Info("trossd starting", "version", opts.Version, "dry_run", cfg.Daemon.DryRun, "links", len(cfg.Links))

	bus := event.NewBus()
	st, err := openStore(cfg.Daemon.DataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	logs := opts.Logs
	if logs == nil {
		logs = logring.New(cfg.Log.RingSize)
	}

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

	mon, err := newMonitor(cfg, log, bus)
	if err != nil {
		return err
	}
	coll := newCollector(log, st, mon)

	srv := &http.Server{
		Handler: api.New(api.Options{
			Log:             log,
			Monitor:         mon,
			Store:           st,
			Logs:            logs,
			System:          coll.Last,
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
	// Подписка до запуска монитора: первые смены состояний не теряются.
	linkEvents, unsubscribeLinks := bus.Subscribe(64, event.TopicLinkState)
	bal := &balancer{log: log, dp: dp, mon: mon, policy: cfg.Policies()[model.ClassDefault]}
	wg.Go(func() { bal.run(runCtx, linkEvents) })
	wg.Go(func() { coll.run(runCtx, collectEvery) })
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
	unsubscribeLinks()
	wg.Wait()
	log.Info("trossd stopped")
	return runErr
}

func openStore(dir string) (*store.SQLite, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("data dir: %w", err)
	}
	st, err := store.Open(filepath.Join(dir, dbFile), store.DefaultRetention())
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	return st, nil
}

func newDataplane(cfg *config.Config, log *slog.Logger) (dataplane.Dataplane, error) {
	if cfg.Daemon.DryRun {
		return dataplane.NewFake(log), nil
	}
	return dataplane.NewSystem(log)
}

func newMonitor(cfg *config.Config, log *slog.Logger, bus event.EventBus) (linkmon.LinkMonitor, error) {
	if cfg.Daemon.DryRun {
		return linkmon.NewFake(cfg.ModelLinks(), bus, cfg.Monitor.Interval, uint64(time.Now().UnixNano())), nil
	}
	m := cfg.Monitor
	params := linkhealth.DefaultParams()
	params.Window, params.FailAfter, params.RecoverAfter = m.Window, m.FailAfter, m.RecoverAfter
	params.HTTPFailAfter = m.HTTPCheck.FailAfter
	hh, mm, _ := m.SpeedTest.AtClock()
	probes := make([]linkmon.LinkProbe, 0, len(cfg.Links))
	for _, l := range cfg.Links {
		general, wl := cfg.ProbeTargets(l)
		probes = append(probes, linkmon.LinkProbe{Link: l.Model(), Mark: l.FwMark, Targets: general, Whitelist: wl})
	}
	return linkmon.NewSystem(linkmon.Options{
		Log: log, Bus: bus, Interval: m.Interval, Timeout: m.Timeout, Params: params, TCPTargets: m.TCPTargets,
		HTTPCheck: httpCheckOptions(m.HTTPCheck),
		SpeedTest: linkmon.SpeedTestOptions{URLs: m.SpeedTest.URLs, Hour: hh, Minute: mm, Duration: m.SpeedTest.Duration, MaxBytes: m.SpeedTest.MaxBytes},
	}, probes)
}

func httpCheckOptions(h config.HTTPCheck) linkmon.HTTPCheckOptions {
	if !*h.Enabled {
		return linkmon.HTTPCheckOptions{}
	}
	o := linkmon.HTTPCheckOptions{Interval: h.Interval, Timeout: h.Timeout, DNS: h.DNS}
	for _, u := range h.URLs {
		o.URLs = append(o.URLs, linkmon.HTTPCheckURL{URL: u.URL, Status: u.Status, Body: u.Body, Domestic: u.Domestic})
	}
	return o
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
