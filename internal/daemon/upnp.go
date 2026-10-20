package daemon

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	coredevices "tross/core/devices"
	"tross/core/event"
	"tross/core/model"
	coreupnp "tross/core/upnp"
	"tross/internal/api"
	"tross/internal/config"
	"tross/internal/dataplane"
	"tross/internal/devices"
	"tross/internal/upnp"
)

// upnpSpec — правила ядра пробросов программ.
func upnpSpec(cfg *config.Config) dataplane.UPnPSpec {
	if !cfg.UPnP.Enabled {
		return dataplane.UPnPSpec{}
	}
	s := dataplane.UPnPSpec{Enabled: true, UDPPorts: []uint16{upnp.PortSSDP, upnp.PortNATPMP}, TCPPorts: []uint16{cfg.UPnP.HTTPPort}}
	for _, l := range cfg.UPnPLinks() {
		s.Links = append(s.Links, slices.IndexFunc(cfg.Links, func(x config.Link) bool { return x.ID == l.ID }))
	}
	slices.Sort(s.Links)
	return s
}

// upnpDevices — реестр для службы пробросов.
type upnpDevices struct{ svc *devices.Service }

func (d upnpDevices) ByIP(a netip.Addr) (model.Device, bool) { return d.svc.Registry().ByIP(a) }

func (d upnpDevices) AllowProgram(ctx context.Context, id, desc string) (model.Device, error) {
	return d.svc.AllowProgram(ctx, id, desc)
}

// upnpService — службы пробросов программ: решения, IGD, NAT-PMP/PCP.
type upnpService struct {
	svc   *upnp.Service
	igd   *upnp.IGD
	cfg   *config.Config
	inLAN func(netip.Addr) bool
	log   *slog.Logger
}

// newUPnPService — nil, если выключено или «сухой» режим (на машине
// разработчика службы не слушают).
func newUPnPService(cfg *config.Config, dp dataplane.Dataplane, devSvc *devices.Service, log *slog.Logger, bus event.EventBus) *upnpService {
	if !cfg.UPnP.Enabled || cfg.Daemon.DryRun {
		return nil
	}
	inLAN := func(a netip.Addr) bool {
		return a.Is4() && slices.ContainsFunc(cfg.LAN.Networks, func(p netip.Prefix) bool { return p.Contains(a) })
	}
	links := cfg.UPnPLinks()
	svc := upnp.New(upnp.Options{
		Kernel: dp, Devices: upnpDevices{devSvc}, Log: log, Bus: bus,
		Limits: coreupnp.Limits{MinPort: 1024, MaxLease: cfg.UPnP.MaxLease, MaxPerDevice: cfg.UPnP.MaxPerDevice},
		Taken:  manualTaken(cfg),
		// Внешний адрес — основного канала пробросов (по приоритету).
		External: func() netip.Addr { return ifaceAddr(links[0].Interface) },
		Online:   func(d model.Device) bool { return time.Since(d.LastSeen) <= coredevices.OnlineWindow },
	})
	lan := netip.AddrPortFrom(cfg.LAN.DHCP.Gateway, cfg.UPnP.HTTPPort)
	return &upnpService{svc: svc, igd: upnp.NewIGD(svc, lan, inLAN, log), cfg: cfg, inLAN: inLAN, log: log}
}

// manualTaken — порт занят ручным пробросом (на любом канале: не
// разбираться, пересекаются ли их каналы).
func manualTaken(cfg *config.Config) coreupnp.Taken {
	return func(proto model.Protocol, port uint16) bool {
		for _, f := range cfg.Inbound.Forwards {
			if f.Port.Contains(port) && slices.Contains(f.Protos(), proto) {
				return true
			}
		}
		return false
	}
}

func ifaceAddr(name string) netip.Addr {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return netip.Addr{}
	}
	as, _ := ifc.Addrs()
	for _, a := range as {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP.To4()); ok {
				return ip
			}
		}
	}
	return netip.Addr{}
}

// run — службы до отмены ctx; служба, которая не открылась, — в журнал.
func (u *upnpService) run(ctx context.Context) {
	var wg sync.WaitGroup
	start := func(name string, f func() error) {
		wg.Go(func() {
			if err := f(); err != nil && ctx.Err() == nil {
				u.log.Error("upnp: service stopped", "service", name, "err", err)
			}
		})
	}
	wg.Go(func() { u.svc.Run(ctx) })
	start("igd-http", func() error { return u.igd.ServeHTTP(ctx) })
	start("ssdp", func() error { return u.igd.ServeSSDP(ctx, u.cfg.LAN.Interface, u.inLAN, u.log) })
	start("nat-pmp", func() error { return upnp.ServePMP(ctx, u.svc, u.cfg.LAN.DHCP.Gateway, u.inLAN, u.log) })
	wg.Wait()
}

// upnpAPI — пробросы программ для API.
type upnpAPI struct {
	u   *upnpService
	reg *coredevices.Registry
}

func (a *upnpAPI) Status(ctx context.Context) (api.UPnPStatus, error) {
	st := api.UPnPStatus{Enabled: a.u != nil}
	if a.u == nil {
		return st, nil
	}
	st.ExternalIP = a.u.svc.ExternalIP()
	ms, err := a.u.svc.Mappings(ctx)
	if err != nil {
		return st, err
	}
	for _, m := range ms {
		e := api.UPnPMapping{UPnPMapping: m, ExpiresSeconds: int(m.Expires / time.Second)}
		if d, ok := a.reg.ByIP(m.Addr); ok {
			e.Device, e.Name = d.ID, d.Name
		}
		st.Mappings = append(st.Mappings, e)
	}
	st.Pending = a.u.svc.Pending()
	return st, nil
}

func (a *upnpAPI) Resolve(ctx context.Context, id, decision string) error {
	if a.u == nil {
		return api.ErrUPnPOff
	}
	d, err := a.u.svc.Resolve(ctx, id, decision)
	switch {
	case errors.Is(err, upnp.ErrNoPending):
		return api.ErrNoPending
	case errors.Is(err, upnp.ErrNotAllowed), errors.Is(err, coredevices.ErrInvalid):
		return api.ErrBadRequest(err)
	case err != nil:
		return err
	case decision != "deny" && d.Outcome != coreupnp.Allow:
		return api.ErrBadRequest(errors.New("cannot open now: " + d.Note))
	}
	return nil
}

func (a *upnpAPI) Close(ctx context.Context, proto model.Protocol, port uint16) error {
	if a.u == nil {
		return api.ErrUPnPOff
	}
	if err := a.u.svc.Unmap(ctx, netip.Addr{}, proto, port); errors.Is(err, upnp.ErrNoSuchEntry) {
		return api.ErrNoPending
	} else {
		return err
	}
}
