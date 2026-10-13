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
	log *slog.Logger
	mu  sync.Mutex
	ops []string
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
