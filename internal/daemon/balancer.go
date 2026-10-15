package daemon

import (
	"context"
	"log/slog"
	"slices"
	"sync"
	"time"

	"tross/core/decision"
	"tross/core/event"
	"tross/core/model"
	"tross/internal/dataplane"
	"tross/internal/linkmon"
)

// rebalanceEvery — пересчёт по таймеру: веса зависят от измеренной скорости,
// а она меняется без смены состояния каналов; заодно сверяются маршруты
// каналов (интерфейс могли пересоздать).
const rebalanceEvery = 30 * time.Second

// balancer связывает монитор с dataplane: распределение новых соединений
// пересчитывается при смене состояния любого канала и по таймеру; у канала,
// ставшего непригодным, сбрасываются соединения — клиенты переподключаются
// через живые каналы, а не ждут таймаутов.
type balancer struct {
	log    *slog.Logger
	dp     dataplane.Dataplane
	mon    linkmon.LinkMonitor
	engine *decision.Engine

	mu      sync.Mutex // current читает API (объяснение решений)
	current []decision.ClassPlan
	usable  map[model.LinkID]bool
}

// applied — план, который сейчас стоит в ядре; nil — первого плана ещё не было.
func (b *balancer) applied() []decision.ClassPlan {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.current
}

// newBalancer — распределения и закрепления по классам считает движок решений.
func newBalancer(log *slog.Logger, dp dataplane.Dataplane, mon linkmon.LinkMonitor, policies map[model.TrafficClass]model.Policy) (*balancer, error) {
	e, err := decision.NewEngine(policies, nil)
	if err != nil {
		return nil, err
	}
	return &balancer{log: log, dp: dp, mon: mon, engine: e}, nil
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
			b.tick(ctx)
		}
	}
}

// tick — работа по таймеру: сначала вернуть пропавшие маршруты каналов (без
// них пробы монитора не проходят и канал не вернулся бы), затем пересчёт.
func (b *balancer) tick(ctx context.Context) {
	if err := b.dp.RepairRoutes(ctx); err != nil {
		b.log.Warn("repair link routes", "err", err)
	}
	b.apply(ctx)
}

func (b *balancer) apply(ctx context.Context) {
	status := b.mon.Snapshot()
	// До первого раунда монитора все каналы unknown: «пригодных нет» стёрло бы
	// стартовый выбор dataplane (первый канал по приоритету).
	if !slices.ContainsFunc(status, func(s model.LinkStatus) bool { return s.Health.State != model.LinkStateUnknown }) {
		return
	}
	b.engine.UpdateLinks(status)
	plan := b.engine.Plan()
	if !slices.EqualFunc(plan, b.current, decision.ClassPlan.Equal) {
		// При ошибке current не меняется — следующий пересчёт повторит; сброс
		// соединений упавшего канала ниже от неё не зависит.
		if err := b.dp.SetPlan(ctx, plan); err != nil {
			b.log.Error("plan apply failed", "err", err)
		} else {
			for _, p := range plan {
				b.log.Info("plan", "class", p.Class, "shares", p.Shares, "pins", p.PinLinks)
			}
			b.mu.Lock()
			b.current = plan
			b.mu.Unlock()
		}
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
