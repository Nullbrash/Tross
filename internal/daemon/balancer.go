package daemon

import (
	"context"
	"log/slog"
	"slices"
	"time"

	"tross/core/decision"
	"tross/core/event"
	"tross/core/model"
	"tross/internal/dataplane"
	"tross/internal/linkmon"
)

// rebalanceEvery — пересчёт по таймеру: веса зависят от измеренной скорости,
// а она меняется без смены состояния каналов.
const rebalanceEvery = 30 * time.Second

// balancer связывает монитор с dataplane: распределение новых соединений
// пересчитывается при смене состояния любого канала и по таймеру; у канала,
// ставшего непригодным, сбрасываются соединения — клиенты переподключаются
// через живые каналы, а не ждут таймаутов.
type balancer struct {
	log    *slog.Logger
	dp     dataplane.Dataplane
	mon    linkmon.LinkMonitor
	policy model.Policy

	current []decision.LinkShare
	usable  map[model.LinkID]bool
}

func (b *balancer) run(ctx context.Context, events <-chan event.Event) {
	t := time.NewTicker(rebalanceEvery)
	defer t.Stop()
	b.apply(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-events:
			if !ok {
				return
			}
			b.apply(ctx)
		case <-t.C:
			b.apply(ctx)
		}
	}
}

func (b *balancer) apply(ctx context.Context) {
	status := b.mon.Snapshot()
	// До первого раунда монитора все каналы unknown: «пригодных нет» стёрло бы
	// стартовый выбор dataplane (первый канал по приоритету).
	if !slices.ContainsFunc(status, func(s model.LinkStatus) bool { return s.Health.State != model.LinkStateUnknown }) {
		return
	}
	shares := decision.Balance(b.policy, status)
	if !slices.Equal(shares, b.current) {
		if err := b.dp.SetBalance(ctx, shares); err != nil {
			b.log.Error("balance apply failed", "err", err)
			return
		}
		b.log.Info("balance", "shares", shares)
		b.current = shares
	}

	now := make(map[model.LinkID]bool, len(status))
	for _, s := range status {
		now[s.Link.ID] = s.Health.State.Usable()
	}
	for id, was := range b.usable {
		if was && !now[id] {
			if err := b.dp.FlushConntrack(ctx, id); err != nil {
				b.log.Warn("flush conntrack failed", "link", id, "err", err)
			} else {
				b.log.Info("connections of failed link flushed", "link", id)
			}
		}
	}
	b.usable = now
}
