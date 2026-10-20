package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"time"

	coredpi "tross/core/dpi"
	"tross/core/event"
	"tross/core/model"
	"tross/internal/config"
	"tross/internal/dataplane"
	"tross/internal/dpi"
	"tross/internal/store"
)

// dpiDevicesTTL — устройство со своим зашифрованным DNS остаётся в
// множестве, пока его соединения видны (проверка — раз в минуту).
const dpiDevicesTTL = 10 * time.Minute

// dpiService — обход DPI: решения по доменам на каналах (из базы), лучшая
// стратегия канала, движок на канал, множества обхода для резолвера.
type dpiService struct {
	log    *slog.Logger
	bus    event.EventBus
	st     store.Store
	dp     dataplane.Dataplane
	mgr    *dpi.Manager
	cat    coredpi.Catalog
	allow  []coredpi.Risk
	manual func() []model.DomainRule
	doh    map[netip.Addr]bool
	// links — каналы с движком: номер в Spec.Links.
	links map[model.LinkID]int

	mu       sync.Mutex
	verdicts map[string]map[model.LinkID]coredpi.Verdict
	scores   map[model.LinkID][]coredpi.Score
	strategy map[model.LinkID]*coredpi.Strategy
	used     map[string]time.Time
}

// newDPIService — nil, если обход выключен, движка нет или «сухой» режим:
// резолвер тогда не кладёт адреса в множества обхода.
func newDPIService(ctx context.Context, cfg *config.Config, log *slog.Logger, bus event.EventBus, st store.Store, dp dataplane.Dataplane, spec dataplane.Spec, manual func() []model.DomainRule, doh map[netip.Addr]bool) *dpiService {
	if !cfg.DPI.Enabled || cfg.Daemon.DryRun || len(spec.DPI.Links) == 0 {
		return nil
	}
	cat, err := coredpi.Builtin()
	if err != nil {
		log.Error("dpi: built-in strategies", "err", err)
		return nil
	}
	eng := dpi.Engine{Binary: cfg.DPI.NFQWS, LuaDir: cfg.DPI.LuaDir, Dir: cfg.DPI.Dir, Debug: cfg.DPI.Debug}
	if err := eng.CheckInstall(cfg.DPI.Version); err != nil {
		log.Error("dpi: engine unavailable, bypass is off", "err", err)
		bus.Publish(event.Event{Topic: event.TopicDPI, Data: event.DPIEvent{Msg: "engine unavailable: " + err.Error()}})
		return nil
	}
	s := &dpiService{log: log, bus: bus, st: st, dp: dp, cat: cat, allow: cfg.DPI.AllowRisks, manual: manual, doh: doh,
		links: map[model.LinkID]int{}, verdicts: map[string]map[model.LinkID]coredpi.Verdict{},
		strategy: map[model.LinkID]*coredpi.Strategy{}, used: map[string]time.Time{}}
	var lcs []dpi.LinkConfig
	for _, l := range spec.DPI.Links {
		ls := spec.Links[l.Index]
		s.links[ls.Link.ID] = l.Index
		lcs = append(lcs, dpi.LinkConfig{Link: ls.Link.ID, Queue: l.Queue, DPIMark: dataplane.DPIMark})
	}
	s.mgr = dpi.NewManager(eng, dpi.ExecRunner{}, lcs, func(e dpi.Event) {
		log.Info("dpi", "link", e.Link, "msg", e.Msg)
		bus.Publish(event.Event{Topic: event.TopicDPI, Data: event.DPIEvent{Link: e.Link, Msg: e.Msg}})
	})
	if err := s.load(ctx); err != nil {
		log.Warn("dpi: saved verdicts not loaded", "err", err)
	}
	return s
}

// load — решения и итоги стратегий из базы: найденное переживает перезапуск.
func (s *dpiService) load(ctx context.Context) error {
	vs, err := s.st.DPIVerdicts(ctx)
	if err != nil {
		return err
	}
	scores, err := s.st.DPIScores(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range vs {
		if s.verdicts[v.Key] == nil {
			s.verdicts[v.Key] = map[model.LinkID]coredpi.Verdict{}
		}
		s.verdicts[v.Key][v.Link] = v.Verdict
	}
	s.scores = scores
	for l := range s.links {
		s.strategy[l] = s.bestLocked(l)
	}
	return nil
}

// bestLocked — лучшая из разрешённых стратегий канала, открывшая хоть что-то.
func (s *dpiService) bestLocked(link model.LinkID) *coredpi.Strategy {
	allowed := map[string]bool{}
	var order []string
	for _, c := range s.cat.Candidates(s.allow...) {
		allowed[c.ID] = true
		order = append(order, c.ID)
	}
	for _, sc := range coredpi.Ranking(s.scores[link], order) {
		if sc.Opened == 0 || !allowed[sc.Strategy] {
			continue
		}
		st, _ := s.cat.ByID(sc.Strategy)
		return &st
	}
	return nil
}

// bypass — для резолвера: каналы, где домену (ключ — шаблон правила)
// нужен обход и движок канала знает стратегию. Ручное правило обхода —
// желание пользователя: обход на всех таких каналах без проверки.
func (s *dpiService) bypass(key string, layer model.RuleLayer, _ string, _ netip.Addr) []dataplane.SetName {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.used[key] = time.Now()
	var out []dataplane.SetName
	for l, i := range s.links {
		if s.strategy[l] == nil {
			continue
		}
		if layer == model.LayerManual || s.verdicts[key][l].Method == coredpi.MethodDPI {
			out = append(out, dataplane.DPISet(i))
		}
	}
	slices.Sort(out)
	return out
}

// hostsLocked — домены hostlist канала.
func (s *dpiService) hostsLocked(link model.LinkID, manual []model.DomainRule) []string {
	var out []string
	for key, byLink := range s.verdicts {
		if byLink[link].Method == coredpi.MethodDPI {
			out = append(out, key)
		}
	}
	for _, r := range manual {
		if r.Purpose == model.PurposeBypass {
			out = append(out, r.Pattern)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// reconcile — стратегии и hostlist каналов к движку; изменилось только
// это — движок не трогается.
func (s *dpiService) reconcile(ctx context.Context) {
	var manual []model.DomainRule
	if s.manual != nil {
		manual = s.manual()
	}
	type job struct {
		link  model.LinkID
		strat *coredpi.Strategy
		hosts []string
	}
	var jobs []job
	s.mu.Lock()
	for l := range s.links {
		hosts := s.hostsLocked(l, manual)
		if s.strategy[l] == nil {
			hosts = nil
		}
		jobs = append(jobs, job{l, s.strategy[l], hosts})
	}
	s.mu.Unlock()
	for _, j := range jobs {
		if err := s.mgr.Apply(ctx, j.link, j.strat, j.hosts); err != nil {
			s.log.Warn("dpi: apply", "link", j.link, "err", err)
		}
	}
}

// setVerdicts — новые решения (автоподбор, тесты): в базу и к движку.
func (s *dpiService) setVerdicts(ctx context.Context, vs []store.DPIVerdict) error {
	if err := s.st.SaveDPIVerdicts(ctx, vs); err != nil {
		return err
	}
	s.mu.Lock()
	for _, v := range vs {
		if s.verdicts[v.Key] == nil {
			s.verdicts[v.Key] = map[model.LinkID]coredpi.Verdict{}
		}
		s.verdicts[v.Key][v.Link] = v.Verdict
	}
	s.mu.Unlock()
	s.reconcile(ctx)
	return nil
}

// setScores — итоги стратегий канала: лучшая становится стратегией движка.
func (s *dpiService) setScores(ctx context.Context, link model.LinkID, scores []coredpi.Score) error {
	if err := s.st.SaveDPIScores(ctx, link, scores); err != nil {
		return err
	}
	s.mu.Lock()
	if s.scores == nil {
		s.scores = map[model.LinkID][]coredpi.Score{}
	}
	s.scores[link] = scores
	s.strategy[link] = s.bestLocked(link)
	s.mu.Unlock()
	s.reconcile(ctx)
	return nil
}

func (s *dpiService) run(ctx context.Context) {
	done := make(chan struct{})
	go func() { s.mgr.Run(ctx); close(done) }()
	s.reconcile(ctx)
	s.refreshDevices(ctx)
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			s.flushUsed(context.Background())
			<-done
			return
		case <-t.C:
		}
		s.flushUsed(ctx)
		s.reconcile(ctx)
		s.refreshDevices(ctx)
	}
}

// flushUsed — когда домены спрашивали, пачкой раз в минуту (беречь SSD).
func (s *dpiService) flushUsed(ctx context.Context) {
	s.mu.Lock()
	keys := make([]string, 0, len(s.used))
	at := time.Time{}
	for k, t := range s.used {
		if _, known := s.verdicts[k]; known {
			keys = append(keys, k)
		}
		if t.After(at) {
			at = t
		}
	}
	clear(s.used)
	s.mu.Unlock()
	if len(keys) == 0 {
		return
	}
	if err := s.st.TouchDPIVerdicts(ctx, keys, at); err != nil {
		s.log.Warn("dpi: usage not saved", "err", err)
	}
}

// refreshDevices — устройства со своим зашифрованным DNS (по соединениям):
// их TLS идёт в очередь целиком, имя проверяет hostlist движка.
func (s *dpiService) refreshDevices(ctx context.Context) {
	conns, err := s.dp.Connections(ctx)
	if err != nil {
		return
	}
	var elems []dataplane.SetElement
	for _, e := range encryptedDNS(conns, s.doh) {
		a, err := netip.ParseAddr(e.Device)
		if err != nil {
			continue
		}
		elems = append(elems, dataplane.SetElement{Set: dataplane.SetDPIDevices, Addr: a, Timeout: dpiDevicesTTL})
	}
	if len(elems) == 0 {
		return
	}
	if err := s.dp.AddToSets(ctx, elems); err != nil {
		s.log.Warn("dpi: devices set", "err", err)
	}
}

// status — состояние движков по каналам (для API).
func (s *dpiService) status() []dpi.LinkStatus {
	if s == nil {
		return nil
	}
	return s.mgr.Status()
}

func (s *dpiService) String() string { return fmt.Sprintf("dpi on %d links", len(s.links)) }
