package linkmon

import (
	"context"
	"math/rand/v2"
	"sync"
	"time"

	"tross/core/event"
	"tross/core/model"
)

// Fake — монитор для «сухого» режима и тестов: правдоподобные, но
// синтетические значения; состояние можно задать вручную через ForceState.
type Fake struct {
	links    []model.Link
	bus      event.EventBus
	interval time.Duration
	now      func() time.Time

	mu     sync.RWMutex
	rnd    *rand.Rand
	health map[model.LinkID]model.LinkHealth
	forced map[model.LinkID]model.LinkState
}

var _ LinkMonitor = (*Fake)(nil)

func NewFake(links []model.Link, bus event.EventBus, interval time.Duration, seed uint64) *Fake {
	f := &Fake{
		links:    links,
		bus:      bus,
		interval: interval,
		now:      time.Now,
		rnd:      rand.New(rand.NewPCG(seed, seed^0x7f4a7c15)),
		health:   make(map[model.LinkID]model.LinkHealth, len(links)),
		forced:   make(map[model.LinkID]model.LinkState),
	}
	for _, l := range links {
		f.health[l.ID] = model.LinkHealth{LinkID: l.ID, State: model.LinkStateUnknown}
	}
	return f
}

func (f *Fake) Run(ctx context.Context) error {
	f.Tick()
	t := time.NewTicker(f.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			f.Tick()
		}
	}
}

// ForceState фиксирует состояние канала (для тестов и сценариев отказа);
// LinkStateUnknown снимает фиксацию.
func (f *Fake) ForceState(id model.LinkID, s model.LinkState) {
	f.mu.Lock()
	if s == model.LinkStateUnknown {
		delete(f.forced, id)
	} else {
		f.forced[id] = s
	}
	f.mu.Unlock()
}

// Tick делает один «замер» всех каналов.
func (f *Fake) Tick() {
	now := f.now()
	var changes []event.LinkStateChange

	f.mu.Lock()
	for i, l := range f.links {
		prev := f.health[l.ID]
		state := model.LinkStateUp
		if s, ok := f.forced[l.ID]; ok {
			state = s
		}
		h := f.sample(i, l, state)
		h.UpdatedAt = now
		h.StateSince = prev.StateSince
		if state != prev.State {
			h.StateSince = now
			changes = append(changes, event.LinkStateChange{Link: l.ID, From: prev.State, To: state, Reason: "fake monitor"})
		}
		f.health[l.ID] = h
	}
	f.mu.Unlock()

	for _, c := range changes {
		f.bus.Publish(event.Event{Topic: event.TopicLinkState, Time: now, Data: c})
	}
}

func (f *Fake) sample(i int, l model.Link, state model.LinkState) model.LinkHealth {
	h := model.LinkHealth{LinkID: l.ID, State: state}
	if state == model.LinkStateDown {
		h.Loss = 1
		return h
	}
	ms := func(base, spread float64) time.Duration {
		return time.Duration((base + f.rnd.Float64()*spread) * float64(time.Millisecond))
	}
	if l.Kind == model.LinkKindLTE {
		h.RTT = ms(45, 25)
		h.Jitter = ms(3, 9)
		h.Loss = f.rnd.Float64() * 0.01
		h.Throughput = model.Throughput{DownBps: 60e6, UpBps: 20e6}
	} else {
		h.RTT = ms(6+3*float64(i), 3)
		h.Jitter = ms(0.3, 1.2)
		h.Throughput = model.Throughput{DownBps: 500e6, UpBps: 500e6}
	}
	return h
}

func (f *Fake) Snapshot() []model.LinkStatus {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make([]model.LinkStatus, 0, len(f.links))
	for _, l := range f.links {
		out = append(out, model.LinkStatus{Link: l, Health: f.health[l.ID]})
	}
	return out
}

func (f *Fake) Status(id model.LinkID) (model.LinkStatus, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	for _, l := range f.links {
		if l.ID == id {
			return model.LinkStatus{Link: l, Health: f.health[id]}, true
		}
	}
	return model.LinkStatus{}, false
}
