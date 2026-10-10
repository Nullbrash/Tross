package store

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"tross/core/event"
	"tross/core/model"
)

// Memory — хранилище в памяти; события ограничены maxEvents (старые вытесняются).
type Memory struct {
	mu        sync.RWMutex
	closed    bool
	devices   map[string]model.Device
	rules     map[RuleKey]model.DomainRule
	events    []event.Event
	maxEvents int
}

var _ Store = (*Memory)(nil)

func NewMemory(maxEvents int) *Memory {
	return &Memory{
		devices:   make(map[string]model.Device),
		rules:     make(map[RuleKey]model.DomainRule),
		maxEvents: max(maxEvents, 1),
	}
}

func (m *Memory) write(fn func()) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	fn()
	return nil
}

func (m *Memory) SaveDevice(_ context.Context, d model.Device) error {
	if d.ID == "" {
		return errors.New("store: device id is empty")
	}
	d.MACs = slices.Clone(d.MACs)
	return m.write(func() { m.devices[d.ID] = d })
}

func (m *Memory) DeleteDevice(_ context.Context, id string) error {
	return m.write(func() { delete(m.devices, id) })
}

func (m *Memory) Devices(context.Context) ([]model.Device, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return nil, ErrClosed
	}
	out := make([]model.Device, 0, len(m.devices))
	for _, d := range m.devices {
		d.MACs = slices.Clone(d.MACs)
		out = append(out, d)
	}
	slices.SortFunc(out, func(a, b model.Device) int { return cmp.Compare(a.ID, b.ID) })
	return out, nil
}

func (m *Memory) SaveRule(_ context.Context, r model.DomainRule) error {
	if err := r.Validate(); err != nil {
		return err
	}
	return m.write(func() { m.rules[KeyOf(r)] = r })
}

func (m *Memory) DeleteRule(_ context.Context, k RuleKey) error {
	return m.write(func() { delete(m.rules, k) })
}

func (m *Memory) Rules(_ context.Context, layer model.RuleLayer) ([]model.DomainRule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return nil, ErrClosed
	}
	var out []model.DomainRule
	for k, r := range m.rules {
		if k.Layer == layer {
			out = append(out, r)
		}
	}
	slices.SortFunc(out, func(a, b model.DomainRule) int {
		return cmp.Or(cmp.Compare(a.Pattern, b.Pattern), cmp.Compare(a.Match, b.Match))
	})
	return out, nil
}

func (m *Memory) AppendEvent(_ context.Context, e event.Event) error {
	return m.write(func() {
		m.events = append(m.events, e)
		if over := len(m.events) - m.maxEvents; over > 0 {
			m.events = slices.Delete(m.events, 0, over)
		}
	})
}

func (m *Memory) Events(_ context.Context, since time.Time, limit int) ([]event.Event, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return nil, ErrClosed
	}
	var out []event.Event
	for _, e := range m.events {
		if !e.Time.Before(since) {
			out = append(out, e)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return slices.Clone(out), nil
}

func (m *Memory) Close() error {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	return nil
}
