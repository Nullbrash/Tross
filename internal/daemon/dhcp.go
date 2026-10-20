package daemon

import (
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"time"

	coredevices "tross/core/devices"
	"tross/core/event"
	"tross/core/model"
	"tross/internal/api"
	"tross/internal/config"
	"tross/internal/devices"
	"tross/internal/dhcp"
)

const (
	// reserveFor — сколько держать закреплённый адрес пропавшего устройства:
	// вернувшийся через неделю телефон получает прежний адрес.
	reserveFor = coredevices.SameWindow
	// probeEvery — пробный запрос в поисках второго DHCP-сервера.
	probeEvery = time.Hour
	// foreignRepeat — событие о том же чужом сервере не чаще.
	foreignRepeat = time.Hour
)

// dhcpService — раздача адресов: закреплённые адреса из реестра, аренды,
// второй сервер в сети.
type dhcpService struct {
	mgr *dhcp.Manager
	reg *coredevices.Registry
	log *slog.Logger
	bus event.EventBus

	kick chan struct{}
	mu   sync.Mutex
	// foreign — чужие серверы, замеченные по ответам с их идентификатором.
	foreign map[netip.Addr]*api.DHCPForeign
}

// newDHCPService — nil, если раздача выключена или «сухой» режим (на машине
// разработчика ни файлов dnsmasq, ни сигналов).
func newDHCPService(cfg *config.Config, reg *coredevices.Registry, log *slog.Logger, bus event.EventBus) *dhcpService {
	d := cfg.LAN.DHCP
	if !d.Enabled || cfg.Daemon.DryRun {
		return nil
	}
	first, last, _ := d.DHCPRange()
	var prefix netip.Prefix
	for _, n := range cfg.LAN.Networks {
		if n.Contains(first) {
			prefix = n.Masked()
		}
	}
	unit := d.Unit
	if unit == "none" {
		unit = ""
	}
	mgr := dhcp.NewManager(dhcp.Config{
		Interface: cfg.LAN.Interface, Prefix: prefix, First: first, Last: last, Gateway: d.Gateway,
		Lease: d.Lease, Dir: d.Dir, PIDFile: d.PIDFile, Unit: unit,
	}, log)
	return &dhcpService{mgr: mgr, reg: reg, log: log, bus: bus, kick: make(chan struct{}, 1), foreign: map[netip.Addr]*api.DHCPForeign{}}
}

// reservations — устройства, виденные за reserveFor, держат свой адрес; у
// объединённой записи он общий для всех её MAC.
func (s *dhcpService) reservations() []dhcp.Reservation {
	c := s.mgr.Config()
	var out []dhcp.Reservation
	seen := map[netip.Addr]bool{}
	for _, d := range s.reg.List() {
		a := d.Addr
		if !a.IsValid() || !c.Prefix.Contains(a) || a == c.Gateway || a == c.Prefix.Addr() || seen[a] || time.Since(d.LastSeen) > reserveFor {
			continue
		}
		seen[a] = true
		out = append(out, dhcp.Reservation{MACs: slices.Clone(d.MACs), Addr: a})
	}
	return out
}

// changed — адреса устройств поменялись (из реестра).
func (s *dhcpService) changed() {
	if s == nil {
		return
	}
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// seed — аренды dnsmasq при старте демона: устройство, продлившее аренду,
// было в сети в момент продления (срок минус длительность аренды).
func (s *dhcpService) seed(ctx context.Context, svc *devices.Service) {
	leases, err := s.mgr.Leases()
	if err != nil {
		s.log.Warn("dhcp: leases", "err", err)
		return
	}
	lease, now := s.mgr.Config().Lease, time.Now()
	for _, l := range leases {
		at := l.Expires.Add(-lease)
		if l.Expires.Before(now) || at.After(now) {
			continue
		}
		_ = svc.Observe(ctx, devices.Observation{MAC: l.MAC, IP: l.Addr, At: at})
	}
}

func (s *dhcpService) run(ctx context.Context, svc *devices.Service, srcs *devices.Sources) {
	if err := s.mgr.Start(ctx, s.reservations()); err != nil {
		s.log.Error("dhcp: start", "err", err)
	}
	s.seed(ctx, svc)
	probe := time.NewTimer(3 * time.Second)
	defer probe.Stop()
	refresh := time.NewTicker(10 * time.Minute)
	defer refresh.Stop()
	update := func() {
		if err := s.mgr.SetReservations(s.reservations()); err != nil {
			s.log.Warn("dhcp: reservations", "err", err)
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.kick:
			// Смена адресов идёт пачками (объединение, первая аренда) —
			// перечитывать dnsmasq раз на пачку.
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
			update()
		case <-refresh.C:
			update()
		case <-probe.C:
			if srcs != nil {
				if err := srcs.ProbeDHCP(); err != nil {
					s.log.Warn("dhcp: probe for other servers", "err", err)
				}
			}
			probe.Reset(probeEvery)
		}
	}
}

// onServer — ответ DHCP-сервера в LAN; не наш — второй раздающий: он
// раздаёт свой шлюз и DNS, устройства получают адреса наугад от двух.
func (s *dhcpService) onServer(server netip.Addr, mac model.MAC) {
	if server == s.mgr.Config().Gateway {
		return
	}
	now := time.Now()
	s.mu.Lock()
	f, ok := s.foreign[server]
	if !ok {
		f = &api.DHCPForeign{Server: server, MAC: mac.String()}
		s.foreign[server] = f
	}
	report := !ok || now.Sub(f.Reported) >= foreignRepeat
	f.LastSeen = now
	if report {
		f.Reported = now
	}
	s.mu.Unlock()
	if report {
		s.log.Warn("dhcp: another DHCP server in the LAN: turn off address assignment in the router", "server", server, "mac", mac)
		if s.bus != nil {
			s.bus.Publish(event.Event{Topic: event.TopicDHCP, Data: event.DHCPEvent{Msg: "another DHCP server in the LAN", Server: server.String(), MAC: mac.String()}})
		}
	}
}

// onServerFunc / statusFunc — nil без раздачи (источникам и API).
func (s *dhcpService) onServerFunc() func(netip.Addr, model.MAC) {
	if s == nil {
		return nil
	}
	return s.onServer
}

func (s *dhcpService) statusFunc() func(context.Context) api.DHCPStatus {
	if s == nil {
		return nil
	}
	return s.status
}

func (s *dhcpService) status(context.Context) api.DHCPStatus {
	c := s.mgr.Config()
	st := api.DHCPStatus{Enabled: true, Range: c.First.String() + "-" + c.Last.String(), Gateway: c.Gateway,
		LeaseSeconds: int(c.Lease / time.Second), Running: s.mgr.Running(), Reservations: len(s.reservations())}
	if ls, err := s.mgr.Leases(); err == nil {
		now := time.Now()
		for _, l := range ls {
			if l.Expires.After(now) {
				st.Leases = append(st.Leases, l)
			}
		}
	}
	s.mu.Lock()
	for _, f := range s.foreign {
		st.Foreign = append(st.Foreign, *f)
	}
	s.mu.Unlock()
	slices.SortFunc(st.Foreign, func(a, b api.DHCPForeign) int { return a.Server.Compare(b.Server) })
	return st
}
