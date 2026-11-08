package daemon

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"tross/core/model"
	"tross/core/profile"
	"tross/internal/api"
	"tross/internal/dataplane"
)

const temporaryForwardIdle = time.Hour

// temporaryForwards держит аварийно открытые TCP-порты только в памяти.
// Проверка слушателя идёт к устройству LAN, а не наружу, и не раскрывает
// существование Tross внешнему адресу.
type temporaryForwards struct {
	mu    sync.Mutex
	dp    dataplane.Dataplane
	apply func(context.Context, []dataplane.PortForward) error
	base  func() []dataplane.PortForward
	items map[string]api.TemporaryForward
	seq   uint64
}

func newTemporaryForwards(dp dataplane.Dataplane, r *reconfigurer) *temporaryForwards {
	return &temporaryForwards{dp: dp, apply: r.setTemporaryForwards, base: func() []dataplane.PortForward {
		r.mu.Lock()
		defer r.mu.Unlock()
		base := len(r.spec.Forwards) - len(r.temporary)
		return append([]dataplane.PortForward{}, r.spec.Forwards[:max(base, 0)]...)
	}, items: map[string]api.TemporaryForward{}}
}

func (t *temporaryForwards) ListTemporaryForwards(context.Context) ([]api.TemporaryForward, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]api.TemporaryForward, 0, len(t.items))
	for _, f := range t.items {
		out = append(out, f)
	}
	slices.SortFunc(out, func(a, b api.TemporaryForward) int { return a.OpenedAt.Compare(b.OpenedAt) })
	return out, nil
}

func (t *temporaryForwards) OpenTemporaryForward(ctx context.Context, req api.TemporaryForwardRequest) (api.TemporaryForward, error) {
	if req.Port == 0 || !req.To.Is4() || req.ToPort == 0 {
		return api.TemporaryForward{}, fmt.Errorf("temporary forward: IPv4 target and ports are required")
	}
	if !t.listens(ctx, req.To, req.ToPort) {
		return api.TemporaryForward{}, fmt.Errorf("temporary forward: TCP port %s is not listening", netip.AddrPortFrom(req.To, req.ToPort))
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, f := range t.base() {
		if f.Ports.From <= req.Port && req.Port <= f.Ports.To && slices.Contains(f.Protos, model.ProtoTCP) {
			return api.TemporaryForward{}, fmt.Errorf("temporary forward: port %d is already used", req.Port)
		}
	}
	for _, f := range t.items {
		if f.Port == req.Port {
			return api.TemporaryForward{}, fmt.Errorf("temporary forward: port %d is already open", req.Port)
		}
	}
	t.seq++
	now := time.Now()
	f := api.TemporaryForward{ID: fmt.Sprintf("tmp-%d", t.seq), Name: req.Name, Port: req.Port, To: req.To, ToPort: req.ToPort, Links: slices.Clone(req.Links), OpenedAt: now, LastInbound: now, ExpiresAt: now.Add(temporaryForwardIdle)}
	t.items[f.ID] = f
	if err := t.applyLocked(ctx); err != nil {
		delete(t.items, f.ID)
		return api.TemporaryForward{}, err
	}
	return f, nil
}

func (t *temporaryForwards) CloseTemporaryForward(ctx context.Context, id string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.items[id]; !ok {
		return fmt.Errorf("temporary forward %q not found", id)
	}
	delete(t.items, id)
	return t.applyLocked(ctx)
}

func (t *temporaryForwards) run(ctx context.Context) {
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			t.sweep(ctx)
		}
	}
}

func (t *temporaryForwards) sweep(ctx context.Context) {
	conns, _ := t.dp.Connections(ctx)
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	changed := false
	for id, f := range t.items {
		active := slices.ContainsFunc(conns, func(c dataplane.Connection) bool { return c.Forward == netip.AddrPortFrom(f.To, f.ToPort) })
		if active {
			f.LastInbound, f.ExpiresAt = now, now.Add(temporaryForwardIdle)
			t.items[id] = f
		}
		if !t.listens(ctx, f.To, f.ToPort) || now.After(f.ExpiresAt) {
			delete(t.items, id)
			changed = true
		}
	}
	if changed {
		_ = t.applyLocked(context.Background())
	}
}

func (t *temporaryForwards) listens(ctx context.Context, addr netip.Addr, port uint16) bool {
	d := net.Dialer{Timeout: time.Second}
	c, err := d.DialContext(ctx, "tcp", netip.AddrPortFrom(addr, port).String())
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func (t *temporaryForwards) applyLocked(ctx context.Context) error {
	forwards := make([]dataplane.PortForward, 0, len(t.items))
	for _, f := range t.items {
		forwards = append(forwards, dataplane.PortForward{Name: f.ID, Protos: []model.Protocol{model.ProtoTCP}, Ports: profile.PortRange{From: f.Port, To: f.Port}, To: f.To, ToPort: f.ToPort, Links: slices.Clone(f.Links)})
	}
	return t.apply(ctx, forwards)
}
