package daemon

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"time"

	coredevices "tross/core/devices"
	"tross/core/model"
	"tross/internal/api"
	"tross/internal/config"
	"tross/internal/dataplane"
	"tross/internal/devices"
)

// deviceBinder — ссылки на устройства в конфиге (MAC, id записи) → адреса
// для ядра: множества правил, режимы DNS, адреса пробросов. Реестр nil —
// только ссылки по IP (очистка после аварии, тесты).
type deviceBinder struct {
	cfg *config.Config
	reg *coredevices.Registry
	dp  dataplane.Dataplane
	log *slog.Logger

	kick chan struct{}
	mu   sync.Mutex
	last dataplane.DeviceBinding
}

func newDeviceBinder(cfg *config.Config, reg *coredevices.Registry, dp dataplane.Dataplane, log *slog.Logger) *deviceBinder {
	return &deviceBinder{cfg: cfg, reg: reg, dp: dp, log: log, kick: make(chan struct{}, 1)}
}

func (b *deviceBinder) addr(r coredevices.Ref) (netip.Addr, bool) {
	if r.Addr.IsValid() {
		return r.Addr, true
	}
	if b == nil || b.reg == nil {
		return netip.Addr{}, false
	}
	return b.reg.AddrOf(r)
}

func (b *deviceBinder) addrs(refs []coredevices.Ref) []netip.Addr {
	var out []netip.Addr
	for _, r := range refs {
		if a, ok := b.addr(r); ok && !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	slices.SortFunc(out, func(x, y netip.Addr) int { return x.Compare(y) })
	return out
}

// configDNS — устройство с режимом DNS из конфига (тот важнее режима,
// заданного через API).
func (b *deviceBinder) configDNS(d model.Device) (model.DNSMode, bool) {
	for _, cd := range b.cfg.DNS.Devices {
		r := cd.Address
		switch {
		case r.Addr.IsValid() && r.Addr == d.Addr,
			!r.MAC.IsZero() && slices.Contains(d.MACs, r.MAC),
			r.ID != "" && (r.ID == d.ID || slices.Contains(d.Aliases, r.ID)):
			return cd.Mode, true
		}
	}
	return "", false
}

func (b *deviceBinder) binding() dataplane.DeviceBinding {
	out := dataplane.DeviceBinding{Rules: map[dataplane.SetName][]netip.Addr{}, DNS: map[netip.Addr]model.DNSMode{}, Forwards: map[string]netip.Addr{}}
	for i, r := range b.cfg.Classify.Rules {
		if len(r.Devices) > 0 {
			out.Rules[dataplane.DeviceSet(i)] = b.addrs(r.Devices)
		}
	}
	if b != nil && b.reg != nil {
		for _, d := range b.reg.List() {
			if d.DNSMode != "" && d.Addr.IsValid() {
				out.DNS[d.Addr] = d.DNSMode
			}
		}
	}
	for _, cd := range b.cfg.DNS.Devices {
		if a, ok := b.addr(cd.Address); ok {
			out.DNS[a] = cd.Mode
		}
	}
	for _, f := range b.cfg.Inbound.Forwards {
		a, _ := b.addr(f.To)
		out.Forwards[f.Name] = a
	}
	return out
}

func bindingEqual(x, y dataplane.DeviceBinding) bool {
	return maps.EqualFunc(x.Rules, y.Rules, slices.Equal) && maps.Equal(x.DNS, y.DNS) && maps.Equal(x.Forwards, y.Forwards)
}

// changed — адреса или режимы устройств поменялись (из реестра).
func (b *deviceBinder) changed() {
	select {
	case b.kick <- struct{}{}:
	default:
	}
}

// run применяет привязку при изменениях; неудача — повтор через минуту.
func (b *deviceBinder) run(ctx context.Context) {
	retry := time.NewTicker(time.Minute)
	defer retry.Stop()
	failed := false
	apply := func() {
		next := b.binding()
		b.mu.Lock()
		same := bindingEqual(next, b.last)
		b.mu.Unlock()
		if same && !failed {
			return
		}
		if err := b.dp.SetDevices(ctx, next); err != nil {
			failed = true
			b.log.Warn("devices: apply addresses to rules", "err", err)
			return
		}
		failed = false
		b.mu.Lock()
		b.last = next
		b.mu.Unlock()
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-b.kick:
			apply()
		case <-retry.C:
			if failed {
				apply()
			}
		}
	}
}

// refs — все имена устройства-источника соединения (для правил по
// устройствам в классификаторе).
func (b *deviceBinder) refs(f model.Flow) []string {
	if b == nil || b.reg == nil || !f.Src.Addr().IsValid() {
		return nil
	}
	return b.reg.RefsOf(f.Src.Addr())
}

// devicesAPI — реестр для API: запись плюс то, что из неё следует.
type devicesAPI struct {
	svc    *devices.Service
	binder *deviceBinder
	def    model.DNSMode
}

func (a *devicesAPI) dto(d model.Device) api.Device {
	out := api.Device{Device: d, Online: time.Since(d.LastSeen) <= coredevices.OnlineWindow,
		SuggestedName: coredevices.SuggestName(d.Hints), UPnPEffective: coredevices.EffectiveUPnP(d)}
	switch m, ok := a.binder.configDNS(d); {
	case ok:
		out.DNSModeEffective, out.DNSModeFrom = m, "config"
	case d.DNSMode != "":
		out.DNSModeEffective, out.DNSModeFrom = d.DNSMode, "device"
	default:
		out.DNSModeEffective, out.DNSModeFrom = a.def, "default"
	}
	return out
}

func (a *devicesAPI) List() []api.Device {
	ds := a.svc.List()
	out := make([]api.Device, len(ds))
	for i, d := range ds {
		out[i] = a.dto(d)
	}
	return out
}

func (a *devicesAPI) Get(ctx context.Context, id string) (api.DeviceDetail, error) {
	d, ok := a.svc.Get(id)
	if !ok {
		return api.DeviceDetail{}, api.ErrNoDevice
	}
	addrs, err := a.svc.Addrs(ctx, id)
	if err != nil {
		return api.DeviceDetail{}, err
	}
	return api.DeviceDetail{Device: a.dto(d), Addrs: addrs}, nil
}

func (a *devicesAPI) Update(ctx context.Context, id string, e api.DeviceEdit) (api.Device, error) {
	d, ok := a.svc.Get(id)
	if !ok {
		return api.Device{}, api.ErrNoDevice
	}
	if _, fixed := a.binder.configDNS(d); fixed && e.DNSMode != nil {
		return api.Device{}, api.ErrConfigured
	}
	d, err := a.svc.Update(ctx, id, coredevices.Edit{Name: e.Name, Type: e.Type, Note: e.Note, DNSMode: e.DNSMode, UPnP: e.UPnP})
	return a.dto(d), apiErr(err)
}

func (a *devicesAPI) Merge(ctx context.Context, dst, src string) (api.Device, error) {
	d, err := a.svc.Merge(ctx, dst, src)
	return a.dto(d), apiErr(err)
}

func (a *devicesAPI) Dismiss(ctx context.Context, id string) (api.Device, error) {
	d, err := a.svc.Dismiss(ctx, id)
	return a.dto(d), apiErr(err)
}

func (a *devicesAPI) Forget(ctx context.Context, id string) error {
	return apiErr(a.svc.Forget(ctx, id))
}

func apiErr(err error) error {
	switch {
	case errors.Is(err, coredevices.ErrNotFound):
		return api.ErrNoDevice
	case errors.Is(err, coredevices.ErrSame), errors.Is(err, coredevices.ErrInvalid):
		return api.ErrBadRequest(err)
	}
	return err
}
