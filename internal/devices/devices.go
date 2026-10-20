// Package devices — реестр клиентов сети по MAC в демоне: источники
// наблюдений на LAN (DHCP, соседи ядра, mDNS, SSDP) и сохранение; логика
// реестра — core/devices.
package devices

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	coredevices "tross/core/devices"
	"tross/core/event"
	"tross/core/model"
	"tross/internal/store"
)

// Observation — факт появления устройства в сети.
type Observation = coredevices.Observation

// Store — то, что реестру нужно от хранилища.
type Store interface {
	SaveDevices(ctx context.Context, ds []model.Device) error
	DeleteDevice(ctx context.Context, id string) error
	Devices(ctx context.Context) ([]model.Device, error)
	MergeDevice(ctx context.Context, dst model.Device, srcID string) error
	TouchDeviceAddrs(ctx context.Context, as []store.DeviceAddr) error
	DeviceAddrs(ctx context.Context, device string) ([]store.DeviceAddr, error)
}

type Options struct {
	Store Store
	Bus   event.EventBus
	Log   *slog.Logger
	// NotifyNew — событие device.new о каждом новом устройстве.
	NotifyNew bool
	// MaxDevices — предел записей: поток выдуманных MAC не раздувает базу.
	MaxDevices int
	// FlushEvery — как часто сохранять «последний раз в сети» и историю
	// адресов (остальное сохраняется сразу).
	FlushEvery time.Duration
	// OnChange — изменились адреса или режимы устройств: пересобрать
	// привязку правил к адресам. Вызывается не под блокировкой реестра.
	OnChange func()
	// Probe — новое устройство получило адрес, а имени mDNS у него нет:
	// спросить имя (один раз за запуск демона).
	Probe func(model.Device)
}

const (
	defaultMaxDevices = 2048
	defaultFlushEvery = 5 * time.Minute
)

var ErrTooMany = errors.New("devices: registry is full")

type addrKey struct {
	mac model.MAC
	ip  netip.Addr
}

// Service — реестр устройств демона.
type Service struct {
	opts Options
	reg  *coredevices.Registry

	mu       sync.Mutex
	seen     map[string]bool // id записей, у которых сдвинулся только LastSeen
	addrs    map[addrKey]store.DeviceAddr
	probed   map[string]bool
	fullWarn time.Time
	// placeholder — когда последний раз писали в журнал о MAC-заглушке с
	// этого адреса.
	placeholder map[netip.Addr]time.Time
}

func New(ctx context.Context, opts Options) (*Service, error) {
	if opts.MaxDevices <= 0 {
		opts.MaxDevices = defaultMaxDevices
	}
	if opts.FlushEvery <= 0 {
		opts.FlushEvery = defaultFlushEvery
	}
	ds, err := opts.Store.Devices(ctx)
	if err != nil {
		return nil, err
	}
	s := &Service{opts: opts, reg: coredevices.NewRegistry(), seen: map[string]bool{}, addrs: map[addrKey]store.DeviceAddr{}, probed: map[string]bool{}, placeholder: map[netip.Addr]time.Time{}}
	s.reg.Load(ds)
	return s, nil
}

// Registry — реестр для чтения (привязка правил, объяснения).
func (s *Service) Registry() *coredevices.Registry { return s.reg }

// Observe учитывает наблюдение источника; безопасен для параллельных вызовов.
func (s *Service) Observe(ctx context.Context, o Observation) error {
	prev, known := s.reg.ByMAC(o.MAC)
	if !known && s.reg.Len() >= s.opts.MaxDevices {
		s.mu.Lock()
		warn := time.Since(s.fullWarn) > time.Minute
		if warn {
			s.fullWarn = time.Now()
		}
		s.mu.Unlock()
		if warn {
			s.opts.Log.Warn("devices: registry full, new device ignored", "max", s.opts.MaxDevices, "mac", o.MAC)
		}
		return ErrTooMany
	}
	ch, err := s.reg.Observe(o)
	if errors.Is(err, coredevices.ErrPlaceholder) {
		s.notePlaceholder(o)
		return err
	}
	if err != nil {
		return err
	}
	d := ch.Device
	s.mu.Lock()
	if o.IP.IsValid() {
		k := addrKey{o.MAC, o.IP}
		a, ok := s.addrs[k]
		if !ok {
			a = store.DeviceAddr{Device: d.ID, MAC: o.MAC, IP: o.IP, First: o.At}
		}
		a.Device, a.Last = d.ID, maxTime(a.Last, o.At)
		s.addrs[k] = a
	}
	if !ch.Changed {
		s.seen[d.ID] = true
	}
	probe := s.opts.Probe != nil && d.Addr.IsValid() && d.Hints.MDNSName == "" && !s.probed[d.ID] &&
		o.At.Sub(d.FirstSeen) <= coredevices.OnlineWindow
	if probe {
		s.probed[d.ID] = true
	}
	s.mu.Unlock()

	if ch.Changed || len(ch.Others) > 0 {
		save := append([]model.Device{}, ch.Others...)
		if ch.Changed {
			save = append(save, d)
		}
		if err := s.opts.Store.SaveDevices(ctx, save); err != nil {
			s.opts.Log.Warn("devices: save", "err", err)
		}
	}
	if ch.New {
		s.opts.Log.Info("devices: new device", "id", d.ID, "mac", o.MAC, "vendor", d.Hints.Vendor, "type", d.Type)
		if s.opts.NotifyNew {
			s.publish(event.TopicDeviceNew, d)
		}
	}
	if probe {
		s.opts.Probe(d)
	}
	if d.MaybeSame != nil && (!known || prev.MaybeSame == nil) {
		s.publish(event.TopicDeviceSame, d)
	}
	if d.Addr != prev.Addr || len(ch.Others) > 0 {
		s.changed()
	}
	return nil
}

// notePlaceholder — устройство с MAC-заглушкой: в реестр не попадает,
// в журнал — не чаще раза в час на адрес.
func (s *Service) notePlaceholder(o Observation) {
	s.mu.Lock()
	t, seen := s.placeholder[o.IP]
	write := !seen || o.At.Sub(t) >= time.Hour
	if write {
		if len(s.placeholder) > 256 {
			clear(s.placeholder)
		}
		s.placeholder[o.IP] = o.At
	}
	s.mu.Unlock()
	if write {
		s.opts.Log.Info("devices: placeholder MAC, not registered", "mac", o.MAC, "addr", o.IP,
			"dhcp_hostname", o.Hints.DHCPHostname, "mdns_name", o.Hints.MDNSName, "vendor_class", o.Hints.DHCPVendorClass)
	}
}

func (s *Service) publish(t event.Topic, d model.Device) {
	if s.opts.Bus == nil {
		return
	}
	e := event.DeviceEvent{ID: d.ID, Name: d.Name, Vendor: d.Hints.Vendor, Type: d.Type}
	if d.Name == "" {
		e.Name = coredevices.SuggestName(d.Hints)
	}
	if len(d.MACs) > 0 {
		e.MAC = d.MACs[len(d.MACs)-1].String()
	}
	if d.Addr.IsValid() {
		e.Addr = d.Addr.String()
	}
	if d.MaybeSame != nil {
		e.SameAs, e.Reasons = d.MaybeSame.ID, d.MaybeSame.Reasons
	}
	s.opts.Bus.Publish(event.Event{Topic: t, Data: e})
}

func (s *Service) changed() {
	if s.opts.OnChange != nil {
		s.opts.OnChange()
	}
}

// Run сохраняет накопленное раз в FlushEvery и при остановке.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(s.opts.FlushEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			// Контекст отменён — сохраняем со своим сроком.
			fctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			s.Flush(fctx)
			cancel()
			return
		case <-t.C:
			s.Flush(ctx)
		}
	}
}

// Flush сохраняет «последний раз в сети» и историю адресов.
func (s *Service) Flush(ctx context.Context) {
	s.mu.Lock()
	ids, addrs := s.seen, s.addrs
	s.seen, s.addrs = map[string]bool{}, map[addrKey]store.DeviceAddr{}
	s.mu.Unlock()
	var ds []model.Device
	for id := range ids {
		if d, ok := s.reg.Get(id); ok {
			ds = append(ds, d)
		}
	}
	if len(ds) > 0 {
		if err := s.opts.Store.SaveDevices(ctx, ds); err != nil {
			s.opts.Log.Warn("devices: save last seen", "err", err)
		}
	}
	var as []store.DeviceAddr
	for _, a := range addrs {
		// Запись могла влиться в другую, пока адрес ждал сохранения.
		if d, ok := s.reg.ByMAC(a.MAC); ok {
			a.Device = d.ID
			as = append(as, a)
		}
	}
	if len(as) > 0 {
		if err := s.opts.Store.TouchDeviceAddrs(ctx, as); err != nil {
			s.opts.Log.Warn("devices: save addresses", "err", err)
		}
	}
}

func (s *Service) List() []model.Device { return s.reg.List() }

func (s *Service) Get(id string) (model.Device, bool) { return s.reg.Get(id) }

func (s *Service) Update(ctx context.Context, id string, e coredevices.Edit) (model.Device, error) {
	before, _ := s.reg.Get(id)
	d, err := s.reg.Update(id, e)
	if err != nil {
		return d, err
	}
	if err := s.opts.Store.SaveDevices(ctx, []model.Device{d}); err != nil {
		return d, err
	}
	if d.DNSMode != before.DNSMode {
		s.changed()
	}
	return d, nil
}

// Merge вливает src в dst (решение пользователя) и сохраняет одной
// транзакцией; история адресов src переходит к dst.
func (s *Service) Merge(ctx context.Context, dstID, srcID string) (model.Device, error) {
	// Сначала — накопленное: иначе адреса src сохранились бы после переноса.
	s.Flush(ctx)
	d, others, err := s.reg.Merge(dstID, srcID)
	if err != nil {
		return d, err
	}
	if err := s.opts.Store.MergeDevice(ctx, d, srcID); err != nil {
		return d, err
	}
	if len(others) > 0 {
		if err := s.opts.Store.SaveDevices(ctx, others); err != nil {
			return d, err
		}
	}
	s.opts.Log.Info("devices: merged", "into", dstID, "from", srcID)
	s.changed()
	return d, nil
}

// AllowProgram — «разрешить всегда» программе устройства.
func (s *Service) AllowProgram(ctx context.Context, id, desc string) (model.Device, error) {
	d, err := s.reg.AllowProgram(id, desc)
	if err != nil {
		return d, err
	}
	return d, s.opts.Store.SaveDevices(ctx, []model.Device{d})
}

func (s *Service) Dismiss(ctx context.Context, id string) (model.Device, error) {
	d, err := s.reg.Dismiss(id)
	if err != nil {
		return d, err
	}
	return d, s.opts.Store.SaveDevices(ctx, []model.Device{d})
}

func (s *Service) Forget(ctx context.Context, id string) error {
	if err := s.reg.Forget(id); err != nil {
		return err
	}
	s.mu.Lock()
	delete(s.seen, id)
	for k, a := range s.addrs {
		if a.Device == id {
			delete(s.addrs, k)
		}
	}
	s.mu.Unlock()
	if err := s.opts.Store.DeleteDevice(ctx, id); err != nil {
		return err
	}
	s.changed()
	return nil
}

// Addrs — история адресов устройства, свежие первыми.
func (s *Service) Addrs(ctx context.Context, id string) ([]store.DeviceAddr, error) {
	s.Flush(ctx)
	return s.opts.Store.DeviceAddrs(ctx, id)
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}
