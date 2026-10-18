package daemon

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"slices"
	"sync"
	"time"

	corelists "tross/core/lists"
	"tross/core/model"
	"tross/internal/api"
	"tross/internal/config"
	"tross/internal/dataplane"
	"tross/internal/linkmon"
	listload "tross/internal/lists"
	"tross/internal/resolver"
	"tross/internal/store"
)

// domainRules — слои доменных правил: встроенный, ручные из конфига,
// выученные из базы; онлайн добавит менеджер списков.
func domainRules(ctx context.Context, cfg *config.Config, st store.Store, log *slog.Logger) (*corelists.Rules, error) {
	r := corelists.NewRules()
	if err := r.SetBuiltin(corelists.Builtin()); err != nil {
		return nil, err
	}
	if err := r.SetManual(cfg.Lists.ManualRules()); err != nil {
		// Конфиг проверен — сюда попадает лишь то, что пропустила проверка.
		log.Warn("lists: some manual rules rejected", "err", err)
	}
	learned, err := st.Rules(ctx, model.LayerLearned)
	if err != nil {
		return nil, err
	}
	for _, l := range learned {
		if err := r.Learn(l); err != nil {
			log.Warn("lists: learned rule rejected", "pattern", l.Pattern, "err", err)
		}
	}
	return r, nil
}

// newListManager — онлайн-списки: кеш в каталоге данных, загрузка — только
// в рабочем режиме, через исправные неплатные каналы по приоритету.
func newListManager(cfg *config.Config, log *slog.Logger, rules *corelists.Rules, mon linkmon.LinkMonitor, spec dataplane.Spec) *listload.Manager {
	opts := listload.Options{Sources: cfg.Lists.Sources, Interval: cfg.Lists.UpdateInterval, Rules: rules, Log: log}
	if cfg.Daemon.DataDir != "" {
		opts.Dir = filepath.Join(cfg.Daemon.DataDir, "lists")
	}
	if !cfg.Daemon.DryRun {
		nets := map[model.LinkID]resolver.LinkNet{}
		for _, l := range spec.Links {
			nets[l.Link.ID] = resolver.LinkNet{Interface: l.Link.Interface, Mark: l.FwMark}
		}
		dns := slices.Clone(cfg.DNS.Listen)
		if cfg.DNS.Fallback.IsValid() {
			dns = append(dns, cfg.DNS.Fallback.String())
		}
		links := func() []model.LinkID {
			var st []model.LinkStatus
			for _, s := range mon.Snapshot() {
				if s.Health.State.Usable() && !s.Link.Metered {
					st = append(st, s)
				}
			}
			slices.SortStableFunc(st, func(a, b model.LinkStatus) int { return cmp.Compare(a.Link.Priority, b.Link.Priority) })
			out := make([]model.LinkID, len(st))
			for i, s := range st {
				out[i] = s.Link.ID
			}
			return out
		}
		dial := resolver.LinkDialer(nets, 15*time.Second)
		opts.Fetch = listload.HTTPFetcher(links, listload.LinkDialer(dial), dns, 5*time.Minute)
	}
	return listload.New(opts)
}

// listsAPI — списки и ручные правила для API. Правила из API хранятся в
// базе; правила конфига через API не удаляются (правятся в конфиге).
type listsAPI struct {
	mgr         *listload.Manager
	rules       *corelists.Rules
	st          store.Store
	config      []model.DomainRule
	classExists func(model.TrafficClass) bool

	mu     sync.Mutex
	stored []model.DomainRule
}

func newListsAPI(ctx context.Context, cfg *config.Config, mgr *listload.Manager, rules *corelists.Rules, st store.Store, log *slog.Logger) (*listsAPI, error) {
	a := &listsAPI{mgr: mgr, rules: rules, st: st, config: cfg.Lists.ManualRules(),
		classExists: func(c model.TrafficClass) bool { _, ok := cfg.Policies()[c]; return ok }}
	stored, err := st.Rules(ctx, model.LayerManual)
	if err != nil {
		return nil, err
	}
	a.stored = stored
	if err := a.applyLocked(); err != nil {
		log.Warn("lists: some manual rules rejected", "err", err)
	}
	return a, nil
}

func (a *listsAPI) applyLocked() error {
	return a.rules.SetManual(append(slices.Clone(a.config), a.stored...))
}

func (a *listsAPI) Sources() []corelists.SourceStatus { return a.mgr.Sources() }

func (a *listsAPI) Refresh(ctx context.Context, id string) error { return a.mgr.Refresh(ctx, id) }

func (a *listsAPI) Manual() []model.DomainRule {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append(slices.Clone(a.config), a.stored...)
}

func (a *listsAPI) AddManual(ctx context.Context, m api.ManualRule) error {
	d, err := corelists.NormalizeName(m.Domain)
	if err != nil {
		return err
	}
	r := model.DomainRule{Pattern: d, Match: model.MatchSuffix, Layer: model.LayerManual, Purpose: m.Purpose, Class: m.Class, Source: "api"}
	if m.Exact {
		r.Match = model.MatchExact
	}
	if r.Purpose == "" || !r.Purpose.Valid() {
		return fmt.Errorf("purpose: want bypass, class, never or inside, got %q", m.Purpose)
	}
	if r.Purpose == model.PurposeClass && !a.classExists(r.Class) {
		return fmt.Errorf("unknown class %q", r.Class)
	}
	if r.Purpose != model.PurposeClass && r.Class != "" {
		return fmt.Errorf("class is only allowed with purpose class")
	}
	if err := r.Validate(); err != nil {
		return err
	}
	if err := a.st.SaveRule(ctx, r); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stored = slices.DeleteFunc(a.stored, func(o model.DomainRule) bool { return o.Pattern == r.Pattern && o.Match == r.Match })
	a.stored = append(a.stored, r)
	return a.applyLocked()
}

func (a *listsAPI) DeleteManual(ctx context.Context, pattern string, match model.MatchKind) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	i := slices.IndexFunc(a.stored, func(o model.DomainRule) bool { return o.Pattern == pattern && o.Match == match })
	if i < 0 {
		return api.ErrNotFound
	}
	if err := a.st.DeleteRule(ctx, store.RuleKey{Layer: model.LayerManual, Match: match, Pattern: pattern}); err != nil {
		return err
	}
	a.stored = slices.Delete(a.stored, i, i+1)
	return a.applyLocked()
}
