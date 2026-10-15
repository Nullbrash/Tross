package dataplane

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"tross/core/decision"
	"tross/core/model"
)

// Fake ничего не меняет в системе: только записывает и логирует вызовы.
type Fake struct {
	log     *slog.Logger
	mu      sync.Mutex
	ops     []string
	conns   []Connection
	pins    []Pin
	shaping map[model.LinkID]Shaping
}

var _ Dataplane = (*Fake)(nil)

func NewFake(log *slog.Logger) *Fake { return &Fake{log: log} }

func (f *Fake) record(op string, args ...any) {
	s := op
	if len(args) > 0 {
		s = fmt.Sprintf("%s %v", op, args)
	}
	f.mu.Lock()
	f.ops = append(f.ops, s)
	f.mu.Unlock()
	f.log.Debug("dry-run dataplane", "op", s)
}

// Ops — журнал вызовов (для тестов).
func (f *Fake) Ops() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.ops...)
}

func (f *Fake) Setup(_ context.Context, spec Spec) error {
	for _, l := range spec.Links {
		f.record("link", l.Link.ID, l.Link.Interface, fmt.Sprintf("table=%d", l.Table), fmt.Sprintf("mark=%#x", l.FwMark))
	}
	for _, fw := range spec.Forwards {
		f.record("forward", fw.Name, fw.Protos, fw.Ports, fw.To, fw.ToPort, fw.Links)
	}
	f.record("setup", spec.LANInterface)
	return nil
}

func (f *Fake) Teardown(context.Context) error {
	f.record("teardown")
	return nil
}

func (f *Fake) SetBalance(_ context.Context, shares []decision.LinkShare) error {
	f.record("set-balance", shares)
	return nil
}

func (f *Fake) SetPlan(_ context.Context, plan []decision.ClassPlan) error {
	for _, p := range plan {
		f.record("set-plan", p.Class, p.Shares, p.PinLinks)
	}
	return nil
}

func (f *Fake) AddToSet(_ context.Context, set SetName, addr netip.Addr, ttl time.Duration) error {
	f.record("add-to-set", set, addr, ttl)
	return nil
}

// RepairRoutes в «сухом» режиме чинить нечего; не записывается — вызывается
// по таймеру и засорял бы журнал вызовов.
func (f *Fake) RepairRoutes(context.Context) error { return nil }

func (f *Fake) FlushConntrack(_ context.Context, id model.LinkID) error {
	f.record("flush-conntrack", id)
	return nil
}

// SetObserved задаёт, что вернут Connections и Pins (для тестов).
func (f *Fake) SetObserved(conns []Connection, pins []Pin) {
	f.mu.Lock()
	f.conns, f.pins = conns, pins
	f.mu.Unlock()
}

// Connections в «сухом» режиме — пусто: ядро не трогается.
func (f *Fake) Connections(context.Context) ([]Connection, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Connection(nil), f.conns...), nil
}

func (f *Fake) SetShaping(_ context.Context, shaping []Shaping) error {
	f.mu.Lock()
	if f.shaping == nil {
		f.shaping = map[model.LinkID]Shaping{}
	}
	for _, sh := range shaping {
		f.shaping[sh.Link] = sh
	}
	f.mu.Unlock()
	for _, sh := range shaping {
		f.record("set-shaping", sh.Link, sh.DownBps, sh.UpBps)
	}
	return nil
}

func (f *Fake) CurrentShaping() []Shaping {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Shaping
	for _, sh := range f.shaping {
		out = append(out, sh)
	}
	return out
}

func (f *Fake) Pins(context.Context) ([]Pin, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Pin(nil), f.pins...), nil
}
