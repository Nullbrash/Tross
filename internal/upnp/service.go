// Package upnp — пробросы по запросу программ устройств LAN: службы UPnP
// IGD (SSDP + SOAP), NAT-PMP и PCP только на адресе LAN, решения —
// core/upnp, пробросы — в ядре (dataplane). Сроки пробросов держит ядро.
package upnp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	coredevices "tross/core/devices"
	"tross/core/event"
	"tross/core/model"
	coreupnp "tross/core/upnp"
	"tross/internal/dataplane"
)

// Kernel — пробросы в ядре.
type Kernel interface {
	SetUPnP(ctx context.Context, m dataplane.UPnPMapping) error
	DeleteUPnP(ctx context.Context, proto model.Protocol, port uint16) error
	UPnPMappings(ctx context.Context) ([]dataplane.UPnPMapping, error)
}

// Devices — реестр: кто прислал запрос, его уровень и программы «всегда».
type Devices interface {
	ByIP(netip.Addr) (model.Device, bool)
	AllowProgram(ctx context.Context, id, desc string) (model.Device, error)
}

type Options struct {
	Kernel  Kernel
	Devices Devices
	Log     *slog.Logger
	Bus     event.EventBus
	Limits  coreupnp.Limits
	// Taken — порт занят ручным пробросом.
	Taken coreupnp.Taken
	// External — внешний адрес для программ (основной канал).
	External func() netip.Addr
	// Online — устройство в сети: пробросы «навсегда» продлеваются, пока да.
	Online func(model.Device) bool
}

var (
	ErrNoSuchEntry = errors.New("upnp: no such mapping")
	ErrNotAllowed  = errors.New("upnp: not allowed")
	ErrNoPending   = errors.New("upnp: no such pending request")
)

// Pending — запрос устройства с уровнем «спрашивать», ждёт решения.
type Pending struct {
	ID      string         `json:"id"`
	Device  string         `json:"device"`
	Name    string         `json:"name,omitempty"`
	Addr    netip.Addr     `json:"addr"`
	Proto   model.Protocol `json:"proto"`
	ExtPort uint16         `json:"ext_port"`
	IntPort uint16         `json:"int_port"`
	Lease   time.Duration  `json:"-"`
	Desc    string         `json:"desc,omitempty"`
	Via     coreupnp.Via   `json:"via"`
	At      time.Time      `json:"at"`
	req     coreupnp.Request
}

type mapKey struct {
	proto model.Protocol
	port  uint16
}

type askKey struct {
	device, desc string
	proto        model.Protocol
	port         uint16
}

const (
	maxPending    = 64
	pendingTTL    = 24 * time.Hour
	denyFor       = 24 * time.Hour
	refuseRepeat  = 10 * time.Minute
	maxRefuseKeys = 1024
)

// Service — пробросы программ.
type Service struct {
	opts  Options
	start time.Time

	// mu — одно решение за раз: два запроса одного порта не должны оба
	// увидеть его свободным.
	mu        sync.Mutex
	pending   map[string]*Pending
	denied    map[askKey]time.Time
	refused   map[askKey]time.Time
	permanent map[mapKey]dataplane.UPnPMapping
}

func New(opts Options) *Service {
	if opts.Limits == (coreupnp.Limits{}) {
		opts.Limits = coreupnp.DefaultLimits()
	}
	return &Service{opts: opts, start: time.Now(), pending: map[string]*Pending{}, denied: map[askKey]time.Time{},
		refused: map[askKey]time.Time{}, permanent: map[mapKey]dataplane.UPnPMapping{}}
}

// Epoch — секунды с запуска (NAT-PMP, PCP: клиент по сбросу понимает, что
// пробросы надо поставить заново).
func (s *Service) Epoch() uint32 { return uint32(time.Since(s.start) / time.Second) }

func (s *Service) ExternalIP() netip.Addr {
	if s.opts.External == nil {
		return netip.IPv4Unspecified()
	}
	if a := s.opts.External(); a.IsValid() {
		return a
	}
	return netip.IPv4Unspecified()
}

func (s *Service) existing(ctx context.Context) ([]dataplane.UPnPMapping, []coreupnp.Mapping, error) {
	ms, err := s.opts.Kernel.UPnPMappings(ctx)
	if err != nil {
		return nil, nil, err
	}
	out := make([]coreupnp.Mapping, len(ms))
	for i, m := range ms {
		out[i] = coreupnp.Mapping{Proto: m.Proto, ExtPort: m.ExtPort, Addr: m.Addr, IntPort: m.IntPort}
	}
	return ms, out, nil
}

// Map — запрос программы. Ошибка — сбой ядра (не отказ: отказ — в Decision).
func (s *Service) Map(ctx context.Context, r coreupnp.Request) (coreupnp.Decision, error) {
	r.Desc = strings.TrimSpace(r.Desc)
	s.mu.Lock()
	defer s.mu.Unlock()
	dev, ok := s.opts.Devices.ByIP(r.Source)
	if !ok {
		d := coreupnp.Decision{Outcome: coreupnp.Deny, Reason: coreupnp.NotAuthorized, Note: "unknown device"}
		s.refuseLocked(model.Device{}, r, d)
		return d, nil
	}
	return s.mapLocked(ctx, dev, r, coredevices.EffectiveUPnP(dev))
}

func (s *Service) mapLocked(ctx context.Context, dev model.Device, r coreupnp.Request, level model.UPnPLevel) (coreupnp.Decision, error) {
	kms, ms, err := s.existing(ctx)
	if err != nil {
		return coreupnp.Decision{}, err
	}
	d := coreupnp.Decide(r, level, dev.UPnPPrograms, s.opts.Limits, ms, s.opts.Taken)
	switch d.Outcome {
	case coreupnp.Allow:
		m := dataplane.UPnPMapping{Proto: r.Proto, ExtPort: d.ExtPort, Addr: r.Source, IntPort: r.IntPort, Lease: d.Lease, Desc: r.Desc}
		if err := s.opts.Kernel.SetUPnP(ctx, m); err != nil {
			return coreupnp.Decision{}, err
		}
		k := mapKey{r.Proto, d.ExtPort}
		if d.Permanent {
			s.permanent[k] = m
		} else {
			delete(s.permanent, k)
		}
		renew := slices.ContainsFunc(kms, func(x dataplane.UPnPMapping) bool {
			return x.Proto == m.Proto && x.ExtPort == m.ExtPort && x.Addr == m.Addr && x.IntPort == m.IntPort
		})
		if !renew {
			s.opts.Log.Info("upnp: port opened", "device", dev.ID, "addr", r.Source, "proto", r.Proto, "port", d.ExtPort, "to", r.IntPort, "desc", r.Desc, "via", r.Via, "lease", d.Lease)
			s.publish(event.UPnPEvent{Action: "open", Device: dev.ID, Addr: r.Source.String(), Proto: string(r.Proto), ExtPort: d.ExtPort, IntPort: r.IntPort, Desc: r.Desc, Via: string(r.Via)})
		}
	case coreupnp.Ask:
		k := askKey{dev.ID, strings.ToLower(r.Desc), r.Proto, r.ExtPort}
		if until, ok := s.denied[k]; ok && time.Now().Before(until) {
			d = coreupnp.Decision{Outcome: coreupnp.Deny, Reason: coreupnp.NotAuthorized, Note: "denied by the user"}
			s.refuseLocked(dev, r, d)
			break
		}
		s.addPendingLocked(dev, r, k)
	default:
		s.refuseLocked(dev, r, d)
	}
	return d, nil
}

// refuseLocked — отказ в журнал и событием, не чаще refuseRepeat на тот же
// запрос (программы повторяют запросы).
func (s *Service) refuseLocked(dev model.Device, r coreupnp.Request, d coreupnp.Decision) {
	k := askKey{dev.ID + "|" + r.Source.String(), strings.ToLower(r.Desc), r.Proto, r.ExtPort}
	now := time.Now()
	if t, ok := s.refused[k]; ok && now.Sub(t) < refuseRepeat {
		return
	}
	if len(s.refused) >= maxRefuseKeys {
		for x, t := range s.refused {
			if now.Sub(t) >= refuseRepeat {
				delete(s.refused, x)
			}
		}
	}
	s.refused[k] = now
	s.opts.Log.Info("upnp: request refused", "device", dev.ID, "addr", r.Source, "proto", r.Proto, "port", r.ExtPort, "to", r.IntPort, "desc", r.Desc, "via", r.Via, "why", d.Note)
	s.publish(event.UPnPEvent{Action: "refuse", Device: dev.ID, Addr: r.Source.String(), Proto: string(r.Proto), ExtPort: r.ExtPort, IntPort: r.IntPort, Desc: r.Desc, Via: string(r.Via), Reason: d.Note})
}

func (s *Service) addPendingLocked(dev model.Device, r coreupnp.Request, k askKey) {
	for _, p := range s.pending {
		if (askKey{p.Device, strings.ToLower(p.Desc), p.Proto, p.ExtPort}) == k {
			p.At, p.req = time.Now(), r
			return
		}
	}
	if len(s.pending) >= maxPending {
		var oldest *Pending
		for _, p := range s.pending {
			if oldest == nil || p.At.Before(oldest.At) {
				oldest = p
			}
		}
		delete(s.pending, oldest.ID)
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := dev.Name
	if name == "" {
		name = coredevices.SuggestName(dev.Hints)
	}
	p := &Pending{ID: hex.EncodeToString(b), Device: dev.ID, Name: name, Addr: r.Source, Proto: r.Proto, ExtPort: r.ExtPort,
		IntPort: r.IntPort, Lease: r.Lease, Desc: r.Desc, Via: r.Via, At: time.Now(), req: r}
	s.pending[p.ID] = p
	s.opts.Log.Info("upnp: request waits for the user", "device", dev.ID, "proto", r.Proto, "port", r.ExtPort, "desc", r.Desc, "id", p.ID)
	s.publish(event.UPnPEvent{Action: "ask", Device: dev.ID, Addr: r.Source.String(), Proto: string(r.Proto), ExtPort: r.ExtPort, IntPort: r.IntPort, Desc: r.Desc, Via: string(r.Via)})
}

func (s *Service) publish(e event.UPnPEvent) {
	if s.opts.Bus != nil {
		s.opts.Bus.Publish(event.Event{Topic: event.TopicUPnP, Data: e})
	}
}

// Resolve — решение пользователя по ожидающему запросу: once — открыть
// сейчас, always — запомнить программу устройства и открыть, deny — отказ
// (тот же запрос сутки не спрашивается).
func (s *Service) Resolve(ctx context.Context, id, decision string) (coreupnp.Decision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[id]
	if !ok {
		return coreupnp.Decision{}, ErrNoPending
	}
	switch decision {
	case "once", "always":
	case "deny":
		delete(s.pending, id)
		s.denied[askKey{p.Device, strings.ToLower(p.Desc), p.Proto, p.ExtPort}] = time.Now().Add(denyFor)
		return coreupnp.Decision{Outcome: coreupnp.Deny, Reason: coreupnp.NotAuthorized, Note: "denied by the user"}, nil
	default:
		return coreupnp.Decision{}, fmt.Errorf("%w: decision %q: want once, always or deny", ErrNotAllowed, decision)
	}
	dev, ok := s.opts.Devices.ByIP(p.Addr)
	if !ok || dev.ID != p.Device {
		delete(s.pending, id)
		return coreupnp.Decision{}, fmt.Errorf("%w: the device has another address now", ErrNoPending)
	}
	if decision == "always" {
		if p.Desc == "" {
			return coreupnp.Decision{}, fmt.Errorf("%w: the program gave no description — allow once", ErrNotAllowed)
		}
		var err error
		if dev, err = s.opts.Devices.AllowProgram(ctx, dev.ID, p.Desc); err != nil {
			return coreupnp.Decision{}, err
		}
	}
	d, err := s.mapLocked(ctx, dev, p.req, model.UPnPAllow)
	if err == nil {
		delete(s.pending, id)
	}
	return d, err
}

func (s *Service) Pending() []Pending {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Pending, 0, len(s.pending))
	for _, p := range s.pending {
		out = append(out, *p)
	}
	slices.SortFunc(out, func(a, b Pending) int { return a.At.Compare(b.At) })
	return out
}

// Unmap — программа (или пользователь, source пуст) снимает проброс.
func (s *Service) Unmap(ctx context.Context, source netip.Addr, proto model.Protocol, port uint16) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	kms, _, err := s.existing(ctx)
	if err != nil {
		return err
	}
	i := slices.IndexFunc(kms, func(m dataplane.UPnPMapping) bool { return m.Proto == proto && m.ExtPort == port })
	if i < 0 {
		return ErrNoSuchEntry
	}
	m := kms[i]
	if source.IsValid() && !coreupnp.CanDelete(source, coreupnp.Mapping{Proto: m.Proto, ExtPort: m.ExtPort, Addr: m.Addr, IntPort: m.IntPort}) {
		return ErrNotAllowed
	}
	if err := s.opts.Kernel.DeleteUPnP(ctx, proto, port); err != nil {
		return err
	}
	delete(s.permanent, mapKey{proto, port})
	dev, _ := s.opts.Devices.ByIP(m.Addr)
	s.opts.Log.Info("upnp: port closed", "device", dev.ID, "addr", m.Addr, "proto", proto, "port", port, "desc", m.Desc)
	s.publish(event.UPnPEvent{Action: "close", Device: dev.ID, Addr: m.Addr.String(), Proto: string(proto), ExtPort: port, IntPort: m.IntPort, Desc: m.Desc})
	return nil
}

// Mappings — пробросы из ядра; Owned — только устройства src.
func (s *Service) Mappings(ctx context.Context) ([]dataplane.UPnPMapping, error) {
	return s.opts.Kernel.UPnPMappings(ctx)
}

func (s *Service) Owned(ctx context.Context, src netip.Addr) ([]dataplane.UPnPMapping, error) {
	ms, err := s.opts.Kernel.UPnPMappings(ctx)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(ms, func(m dataplane.UPnPMapping) bool { return m.Addr != src }), nil
}

// Run — продление пробросов «навсегда», пока устройство в сети, и чистка
// старых ожидающих запросов.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(s.opts.Limits.MaxLease / 3)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.tick(ctx)
		}
	}
}

func (s *Service) tick(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for id, p := range s.pending {
		if now.Sub(p.At) > pendingTTL {
			delete(s.pending, id)
		}
	}
	for k, until := range s.denied {
		if now.After(until) {
			delete(s.denied, k)
		}
	}
	kms, err := s.opts.Kernel.UPnPMappings(ctx)
	if err != nil {
		s.opts.Log.Warn("upnp: list mappings", "err", err)
		return
	}
	// Устройство лишили права — его пробросы снимаются сразу.
	for _, m := range kms {
		if dev, ok := s.opts.Devices.ByIP(m.Addr); !ok || coredevices.EffectiveUPnP(dev) == model.UPnPDeny {
			if err := s.opts.Kernel.DeleteUPnP(ctx, m.Proto, m.ExtPort); err == nil {
				delete(s.permanent, mapKey{m.Proto, m.ExtPort})
				s.publish(event.UPnPEvent{Action: "close", Device: dev.ID, Addr: m.Addr.String(), Proto: string(m.Proto), ExtPort: m.ExtPort, IntPort: m.IntPort, Desc: m.Desc, Reason: "device is not allowed"})
			}
		}
	}
	for k, m := range s.permanent {
		alive := slices.ContainsFunc(kms, func(x dataplane.UPnPMapping) bool {
			return x.Proto == m.Proto && x.ExtPort == m.ExtPort && x.Addr == m.Addr
		})
		dev, ok := s.opts.Devices.ByIP(m.Addr)
		if !alive || !ok || s.opts.Online == nil || !s.opts.Online(dev) || coredevices.EffectiveUPnP(dev) == model.UPnPDeny {
			// Устройство ушло (или его лишили права) — проброс истечёт сам.
			delete(s.permanent, k)
			continue
		}
		if err := s.opts.Kernel.SetUPnP(ctx, m); err != nil {
			s.opts.Log.Warn("upnp: renew", "port", m.ExtPort, "err", err)
		}
	}
}
