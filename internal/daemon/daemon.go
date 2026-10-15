// Package daemon собирает модули демона вместе и управляет их жизненным циклом.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"tross/core/event"
	"tross/core/linkhealth"
	"tross/core/model"
	"tross/core/profile"
	"tross/internal/api"
	"tross/internal/config"
	"tross/internal/dataplane"
	"tross/internal/linkmon"
	"tross/internal/logring"
	"tross/internal/sdnotify"
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
// При любом исходе снимает разметку dataplane; NAT остаётся — без демона
// сеть работает через основную таблицу маршрутизации.
func Run(ctx context.Context, opts Options) error {
	cfg, log := opts.Config, opts.Log
	log.Info("trossd starting", "version", opts.Version, "dry_run", cfg.Daemon.DryRun, "links", len(cfg.Links))

	bus := event.NewBus()
	st, err := openStore(cfg.Daemon.DataDir, log)
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
	spec, err := dataplaneSpec(cfg)
	if err != nil {
		return err
	}
	if err := dp.Setup(ctx, spec); err != nil {
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
	bal, err := newBalancer(log, dp, mon, cfg.Policies())
	if err != nil {
		return fmt.Errorf("decision engine: %w", err)
	}
	cat, err := serviceCatalog(cfg)
	if err != nil {
		return err
	}
	expl, err := newExplainer(cfg, cat, bal, dp)
	if err != nil {
		return fmt.Errorf("classifier: %w", err)
	}

	srv := &http.Server{
		Handler: api.New(api.Options{
			Log:             log,
			Monitor:         mon,
			Store:           st,
			Logs:            logs,
			System:          coll.Last,
			EventDrops:      bus.Dropped,
			Connections:     dp.Connections,
			Explain:         expl.explain,
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
	wg.Go(func() { bal.run(runCtx, linkEvents) })
	wg.Go(func() { coll.run(runCtx, collectEvery) })
	if every := sdnotify.WatchdogInterval(); every > 0 {
		wg.Go(func() { watchdog(runCtx, log, every, mon, cfg.Monitor.Interval) })
	}
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
	// «Готов» — после установки правил и открытия API: systemd считает
	// службу запущенной только теперь (Type=notify).
	if err := sdnotify.Notify("READY=1"); err != nil {
		log.Warn("sd_notify", "err", err)
	}

	var runErr error
	select {
	case <-ctx.Done():
		log.Info("shutdown requested")
	case runErr = <-fatal:
		log.Error("fatal error, shutting down", "err", runErr)
	}

	_ = sdnotify.Notify("STOPPING=1")
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

// openStore — база в каталоге данных; пустой каталог — база в памяти.
func openStore(dir string, log *slog.Logger) (*store.SQLite, error) {
	if dir == "" {
		log.Info("store in memory: no data dir (dry run without -data-dir)")
		return store.Open("", store.DefaultRetention())
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("data dir: %w", err)
	}
	st, err := store.Open(filepath.Join(dir, dbFile), store.DefaultRetention())
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	return st, nil
}

// Cleanup снимает разметку демона без запуска (после аварийного завершения —
// ExecStopPost службы); purge убирает и NAT. В «сухом» режиме снимать нечего.
func Cleanup(ctx context.Context, cfg *config.Config, log *slog.Logger, purge bool) error {
	if cfg.Daemon.DryRun {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, shutdownTimeout)
	defer cancel()
	spec, err := dataplaneSpec(cfg)
	if err != nil {
		return err
	}
	return dataplane.Cleanup(ctx, log, spec, purge)
}

// CleanupWithoutConfig — Cleanup, когда конфиг не читается: таблицы nft и
// ip rule демона снимаются (их не надо знать заранее), маршруты таблиц
// каналов остаются — их номера знает только конфиг.
func CleanupWithoutConfig(ctx context.Context, log *slog.Logger, purge bool) error {
	ctx, cancel := context.WithTimeout(ctx, shutdownTimeout)
	defer cancel()
	return dataplane.Cleanup(ctx, log, dataplane.Spec{}, purge)
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

var dnsProto = map[config.DNSProto]linkmon.DNSProto{
	config.DNSPlain:     linkmon.DNSPlain,
	config.DNSOverTLS:   linkmon.DNSOverTLS,
	config.DNSOverHTTPS: linkmon.DNSOverHTTPS,
}

func httpCheckOptions(h config.HTTPCheck) linkmon.HTTPCheckOptions {
	if !*h.Enabled {
		return linkmon.HTTPCheckOptions{}
	}
	o := linkmon.HTTPCheckOptions{Interval: h.Interval, Timeout: h.Timeout}
	for _, d := range h.DNS {
		o.DNS = append(o.DNS, linkmon.DNSServer{Proto: dnsProto[d.Proto], Addr: d.Addr, URL: d.URL})
	}
	for _, u := range h.URLs {
		o.URLs = append(o.URLs, linkmon.HTTPCheckURL{URL: u.URL, Status: u.Status, Body: u.Body, Domestic: u.Domestic})
	}
	return o
}

func dataplaneSpec(cfg *config.Config) (dataplane.Spec, error) {
	spec := dataplane.Spec{
		LANInterface: cfg.LAN.Interface,
	}
	for _, l := range cfg.Links {
		spec.Links = append(spec.Links, dataplane.LinkSpec{
			Link: l.Model(), Table: l.Table, FwMark: l.FwMark, Gateway: l.GatewayAddr(),
		})
	}
	cat, err := serviceCatalog(cfg)
	if err != nil {
		return spec, err
	}
	var classes []model.TrafficClass
	policies := map[model.TrafficClass]dataplane.ClassPolicy{}
	for _, cl := range cfg.Classes {
		classes = append(classes, cl.ID)
		var allowed []model.LinkID
		if len(cl.Links) > 0 {
			allowed = append(slices.Clone(cl.Links), cl.Fallback...)
		}
		policies[cl.ID] = dataplane.ClassPolicy{Pin: cl.Stickiness, PinTTL: cl.StickyTTL, Allowed: allowed}
	}
	var rules []dataplane.UserRule
	for _, r := range cfg.Classify.Rules {
		rules = append(rules, dataplane.UserRule{Name: r.Name, Class: r.Class, Devices: r.Devices, Match: r.Match})
	}
	spec.Classify = dataplane.CompileClassify(classes, policies, rules, cat)
	for _, f := range cfg.Inbound.Forwards {
		spec.Forwards = append(spec.Forwards, dataplane.PortForward{
			Name: f.Name, Protos: f.Protos(), Ports: f.Port, To: f.To, ToPort: f.ToPort, Links: f.Links,
		})
	}
	g := cfg.Inbound.Guard
	spec.Guard = dataplane.InboundGuard{NewPerMinute: g.NewPerMinute, Burst: g.Burst, MaxConns: g.MaxConnections}
	return spec, nil
}

// serviceCatalog — встроенные профили с правками пользователя поверх.
func serviceCatalog(cfg *config.Config) (profile.Catalog, error) {
	cat, err := profile.Builtin()
	if err != nil {
		return profile.Catalog{}, fmt.Errorf("service catalog: %w", err)
	}
	return cat.WithUser(cfg.Classify.Services), nil
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
