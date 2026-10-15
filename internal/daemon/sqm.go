package daemon

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"tross/core/event"
	"tross/core/model"
	"tross/core/sqm"
	"tross/internal/api"
	"tross/internal/config"
	"tross/internal/dataplane"
)

// sqmEventEvery — не чаще одного события смены скорости на канал: под
// нагрузкой автоподстройка шагает каждые 10–30 с, и каждое в истории событий
// (хранится год) было бы шумом; промежуточные — в журнале.
const sqmEventEvery = time.Minute

// lostDelay — задержка раунда, в котором под нагрузкой не ответила ни одна
// проба: заведомо больше любого порога «раздутости».
const lostDelay = time.Second

// sqmController — очереди CAKE каналов: скорость из замеров и автоподстройки
// по задержке под нагрузкой (core/sqm), применение — dataplane.SetShaping.
type sqmController struct {
	log *slog.Logger
	dp  dataplane.Dataplane
	bus event.EventBus

	mu    sync.Mutex
	links map[model.LinkID]*sqmLink
	order []model.LinkID
}

type sqmLink struct {
	q         *sqm.Link
	delay     sqm.Delay
	testing   bool // идёт тест скорости — загрузка без ограничения
	applied   dataplane.Shaping
	lastEvent time.Time
}

func newSQMController(cfg *config.Config, log *slog.Logger, dp dataplane.Dataplane, bus event.EventBus) *sqmController {
	c := &sqmController{log: log, dp: dp, bus: bus, links: map[model.LinkID]*sqmLink{}}
	for _, l := range cfg.Links {
		if !l.SQM.Enabled {
			continue
		}
		p := l.SQM.Params(l.Kind)
		// applied — как поставил Setup (без ограничения): не повторять.
		c.links[l.ID] = &sqmLink{applied: dataplane.Shaping{Link: l.ID}, q: &sqm.Link{
			Down: sqm.NewShaper(p, uint64(l.SQM.DownMbit)*1_000_000),
			Up:   sqm.NewShaper(p, uint64(l.SQM.UpMbit)*1_000_000),
		}}
		c.order = append(c.order, l.ID)
	}
	return c
}

// start подхватывает скорости очередей, уже стоящих в ядре (они переживают
// остановку демона), и применяет начальные: база из конфига — сразу.
func (c *sqmController) start(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, sh := range c.dp.CurrentShaping() {
		if sl, ok := c.links[sh.Link]; ok {
			sl.q.Down.Restore(sh.DownBps)
			sl.q.Up.Restore(sh.UpBps)
			sl.applied = sh
		}
	}
	for _, id := range c.order {
		c.applyLocked(ctx, id)
	}
}

func (c *sqmController) run(ctx context.Context, rounds <-chan event.Event) {
	for {
		select {
		case <-ctx.Done():
			return
		case e, ok := <-rounds:
			if !ok {
				return
			}
			if r, ok := e.Data.(event.LinkRound); ok {
				c.observe(ctx, e.Time, r)
			}
		}
	}
}

func (c *sqmController) observe(ctx context.Context, at time.Time, r event.LinkRound) {
	c.mu.Lock()
	defer c.mu.Unlock()
	sl, ok := c.links[r.Link]
	if !ok || sl.testing {
		return
	}
	busy := sl.q.Busy(r.DownBps, r.UpBps)
	delay, ok := sl.delay.Observe(r.RTTs, busy)
	if !ok {
		if !busy {
			return
		}
		// Под нагрузкой не ответила ни одна проба: очередь у провайдера
		// длиннее таймаута проб (у LTE буферы на секунды). Это та же
		// «раздутость» — и успеть надо до того, как монитор сочтёт канал
		// упавшим.
		delay = lostDelay
	}
	down, up := sl.q.Observe(sqm.Sample{At: at, DownBps: r.DownBps, UpBps: r.UpBps, Delay: delay})
	if down == "" && up == "" {
		return
	}
	why := down
	if why == "" {
		why = up
	} else if up != "" {
		why = "down " + down + "; up " + up
	}
	c.log.Info("sqm rate", "link", r.Link, "down", down, "up", up)
	c.applyLocked(ctx, r.Link)
	c.eventLocked(at, r.Link, why)
}

// applyLocked — скорость очередей канала в ядро, если изменилась.
func (c *sqmController) applyLocked(ctx context.Context, id model.LinkID) {
	sl := c.links[id]
	sh := dataplane.Shaping{Link: id, DownBps: sl.q.Down.Rate(), UpBps: sl.q.Up.Rate()}
	if sl.testing {
		sh.DownBps = 0
	}
	if sh == sl.applied {
		return
	}
	if err := c.dp.SetShaping(ctx, []dataplane.Shaping{sh}); err != nil {
		c.log.Warn("sqm apply failed", "link", id, "err", err)
		return
	}
	sl.applied = sh
}

func (c *sqmController) eventLocked(at time.Time, id model.LinkID, why string) {
	sl := c.links[id]
	if at.Sub(sl.lastEvent) < sqmEventEvery {
		return
	}
	sl.lastEvent = at
	c.bus.Publish(event.Event{Topic: event.TopicSQM, Time: at,
		Data: event.SQMChange{Link: id, DownBps: sl.applied.DownBps, UpBps: sl.applied.UpBps, Reason: why}})
}

// speedTestHook — на время теста скорости ограничение загрузки снимается:
// иначе тест измерил бы саму очередь; результат — база загрузки.
func (c *sqmController) speedTestHook(id model.LinkID) func(model.Throughput, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	sl, ok := c.links[id]
	if !ok {
		return func(model.Throughput, error) {}
	}
	sl.testing = true
	ctx := context.Background()
	c.applyLocked(ctx, id)
	return func(th model.Throughput, err error) {
		c.mu.Lock()
		defer c.mu.Unlock()
		sl.testing = false
		if err == nil && sl.q.Down.SetTested(th.DownBps) {
			c.log.Info("sqm base from speed test", "link", id, "down", sqm.Mbit(th.DownBps))
			sl.lastEvent = time.Time{}
			c.applyLocked(ctx, id)
			c.eventLocked(time.Now(), id, "speed test "+sqm.Mbit(th.DownBps))
			return
		}
		c.applyLocked(ctx, id)
	}
}

func (c *sqmController) status() map[model.LinkID]api.SQMStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	dir := func(s *sqm.Shaper, rate uint64) api.SQMDirection {
		b, basis := s.Base()
		return api.SQMDirection{RateBps: rate, BaseBps: b, Basis: string(basis), Pct: s.Fraction() * 100}
	}
	out := make(map[model.LinkID]api.SQMStatus, len(c.links))
	for id, sl := range c.links {
		out[id] = api.SQMStatus{Down: dir(sl.q.Down, sl.applied.DownBps), Up: dir(sl.q.Up, sl.applied.UpBps), Testing: sl.testing}
	}
	return out
}
