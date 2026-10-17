package daemon

import (
	"cmp"
	"context"
	"log/slog"
	"path/filepath"
	"slices"
	"time"

	corelists "tross/core/lists"
	"tross/core/model"
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
