//go:build linux

package devices

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"

	"tross/core/model"
)

// Sources — слушатели LAN и опрос имён новых устройств.
type Sources struct {
	opts  SourceOptions
	ifc   *net.Interface
	probe chan netip.Addr

	mu   sync.Mutex
	macs map[netip.Addr]model.MAC // из таблицы соседей: адрес → MAC
	last map[throttleKey]time.Time
}

type throttleKey struct {
	src  netip.Addr
	kind byte
}

// Анонсы mDNS и SSDP идут пачками: с одного адреса учитывается не чаще
// раза в throttle — поток пакетов не превращается в поток записей в реестр.
const throttle = 2 * time.Second

func NewSources(opts SourceOptions) (*Sources, error) {
	ifc, err := net.InterfaceByName(opts.Interface)
	if err != nil {
		return nil, fmt.Errorf("devices: LAN interface: %w", err)
	}
	return &Sources{opts: opts, ifc: ifc, probe: make(chan netip.Addr, 64), macs: map[netip.Addr]model.MAC{}, last: map[throttleKey]time.Time{}}, nil
}

// Run слушает до отмены ctx. Источник, который не открылся, — в журнал:
// остальные работают без него.
func (s *Sources) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for name, run := range map[string]func(context.Context) error{
		"neighbours": s.runNeigh, "dhcp": s.runDHCP, "mdns": s.runMDNS, "ssdp": s.runSSDP, "probe": s.runProbe,
	} {
		wg.Go(func() {
			if err := run(ctx); err != nil && ctx.Err() == nil {
				s.opts.Log.Warn("devices: source stopped", "source", name, "err", err)
			}
		})
	}
	wg.Wait()
}

// Probe — спросить имя устройства по mDNS (очередь; переполнена — пропуск).
func (s *Sources) Probe(d model.Device) {
	select {
	case s.probe <- d.Addr:
	default:
	}
}

func (s *Sources) inLAN(a netip.Addr) bool {
	return a.Is4() && slices.ContainsFunc(s.opts.Networks, func(p netip.Prefix) bool { return p.Contains(a) })
}

func (s *Sources) allow(src netip.Addr, kind byte) bool {
	k, now := throttleKey{src, kind}, time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if now.Sub(s.last[k]) < throttle {
		return false
	}
	s.last[k] = now
	if len(s.last) > 4096 {
		for k, t := range s.last {
			if now.Sub(t) >= throttle {
				delete(s.last, k)
			}
		}
	}
	return true
}

func (s *Sources) macOf(a netip.Addr) (model.MAC, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.macs[a]
	return m, ok
}

// runNeigh — таблица соседей ядра: REACHABLE — устройство только что
// ответило (свидетельство активности); любое состояние с MAC — для
// сопоставления адреса из mDNS и SSDP с MAC.
func (s *Sources) runNeigh(ctx context.Context) error {
	ch := make(chan netlink.NeighUpdate, 256)
	done := make(chan struct{})
	defer close(done)
	errs := make(chan error, 1)
	err := netlink.NeighSubscribeWithOptions(ch, done, netlink.NeighSubscribeOptions{
		ListExisting: true,
		ErrorCallback: func(err error) {
			select {
			case errs <- err:
			default:
			}
		},
	})
	if err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errs:
			return err
		case u, ok := <-ch:
			if !ok {
				return errors.New("neighbour subscription closed")
			}
			s.neigh(u)
		}
	}
}

func (s *Sources) neigh(u netlink.NeighUpdate) {
	if u.LinkIndex != s.ifc.Index || u.Family != unix.AF_INET || len(u.HardwareAddr) != 6 {
		return
	}
	ip, ok := netip.AddrFromSlice(u.IP.To4())
	if !ok || !s.inLAN(ip) {
		return
	}
	var mac model.MAC
	copy(mac[:], u.HardwareAddr)
	s.mu.Lock()
	switch {
	case u.Type == unix.RTM_DELNEIGH || u.State&(netlink.NUD_FAILED|netlink.NUD_INCOMPLETE) != 0:
		if s.macs[ip] == mac {
			delete(s.macs, ip)
		}
	default:
		s.macs[ip] = mac
	}
	s.mu.Unlock()
	if u.Type == unix.RTM_NEWNEIGH && u.State&netlink.NUD_REACHABLE != 0 {
		s.opts.Observe(Observation{MAC: mac, IP: ip, At: time.Now()})
	}
}

// dhcpFilter — только UDP на порты 67 и 68, без фрагментов (смещения — от
// IP-заголовка: сокет SOCK_DGRAM).
var dhcpFilter = []bpf.Instruction{
	bpf.LoadAbsolute{Off: 9, Size: 1},
	bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.IPPROTO_UDP, SkipFalse: 7},
	bpf.LoadAbsolute{Off: 6, Size: 2},
	bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 5},
	bpf.LoadMemShift{Off: 0},
	bpf.LoadIndirect{Off: 2, Size: 2},
	bpf.JumpIf{Cond: bpf.JumpEqual, Val: 67, SkipTrue: 1},
	bpf.JumpIf{Cond: bpf.JumpEqual, Val: 68, SkipFalse: 1},
	bpf.RetConstant{Val: 1600},
	bpf.RetConstant{Val: 0},
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// runDHCP — копии всех сообщений DHCP на LAN (и запросов клиентов, и
// подтверждений сервера), кто бы ни раздавал адреса: сокет пакетного уровня
// не мешает серверу на порту 67.
func (s *Sources) runDHCP(ctx context.Context) error {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_IP)))
	if err != nil {
		return fmt.Errorf("packet socket: %w", err)
	}
	defer unix.Close(fd)
	prog, err := bpf.Assemble(dhcpFilter)
	if err != nil {
		return err
	}
	raw := make([]unix.SockFilter, len(prog))
	for i, in := range prog {
		raw[i] = unix.SockFilter{Code: in.Op, Jt: in.Jt, Jf: in.Jf, K: in.K}
	}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{Len: uint16(len(raw)), Filter: &raw[0]}); err != nil {
		return fmt.Errorf("attach filter: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_IP), Ifindex: s.ifc.Index}); err != nil {
		return fmt.Errorf("bind: %w", err)
	}
	// Таймаут чтения — чтобы заметить отмену ctx.
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}); err != nil {
		return err
	}
	buf := make([]byte, 2048)
	for ctx.Err() == nil {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}
		if o, ok := dhcpObservation(buf[:n], time.Now()); ok {
			s.opts.Observe(o)
		}
	}
	return nil
}

// dhcpObservation — наблюдение по IP-пакету с сообщением DHCP. Фильтр ядра
// ещё не стоял, пока сокет открывался, — порты проверяются и здесь.
func dhcpObservation(p []byte, at time.Time) (Observation, bool) {
	if len(p) < 20 || p[0]>>4 != 4 || p[9] != unix.IPPROTO_UDP {
		return Observation{}, false
	}
	ihl := int(p[0]&0x0f) * 4
	if ihl < 20 || len(p) < ihl+8 {
		return Observation{}, false
	}
	if dport := uint16(p[ihl+2])<<8 | uint16(p[ihl+3]); dport != 67 && dport != 68 {
		return Observation{}, false
	}
	d, err := ParseDHCP(p[ihl+8:])
	if err != nil {
		return Observation{}, false
	}
	return d.Observation(at)
}

// multicast — сокет группы на интерфейсе LAN. SO_REUSEADDR и SO_REUSEPORT —
// порт может держать системная служба (avahi), каждому достаётся копия.
func (s *Sources) multicast(ctx context.Context, port int, group net.IP) (*ipv4.PacketConn, net.PacketConn, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			if serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); serr == nil {
				serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			}
		})
		if err != nil {
			return err
		}
		return serr
	}}
	c, err := lc.ListenPacket(ctx, "udp4", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return nil, nil, err
	}
	p := ipv4.NewPacketConn(c)
	if err := p.JoinGroup(s.ifc, &net.UDPAddr{IP: group}); err != nil {
		c.Close()
		return nil, nil, err
	}
	if err := p.SetControlMessage(ipv4.FlagInterface, true); err != nil {
		c.Close()
		return nil, nil, err
	}
	go func() {
		<-ctx.Done()
		c.Close()
	}()
	return p, c, nil
}

// readLAN — пакеты с интерфейса LAN от адресов LAN.
func (s *Sources) readLAN(ctx context.Context, p *ipv4.PacketConn, handle func([]byte, netip.Addr)) error {
	buf := make([]byte, 9000)
	for {
		n, cm, src, err := p.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		ua, ok := src.(*net.UDPAddr)
		if !ok || cm == nil || cm.IfIndex != s.ifc.Index {
			continue
		}
		a, ok := netip.AddrFromSlice(ua.IP.To4())
		if ok && s.inLAN(a) {
			handle(buf[:n], a)
		}
	}
}

func (s *Sources) hint(src netip.Addr, kind byte, h model.DeviceHints) {
	mac, ok := s.macOf(src)
	if !ok || !s.allow(src, kind) {
		return
	}
	s.opts.Observe(Observation{MAC: mac, IP: src, Hints: h, At: time.Now()})
}

func (s *Sources) runMDNS(ctx context.Context) error {
	p, c, err := s.multicast(ctx, 5353, net.IPv4(224, 0, 0, 251))
	if err != nil {
		return err
	}
	defer c.Close()
	return s.readLAN(ctx, p, func(b []byte, src netip.Addr) {
		if h, ok := ParseMDNS(b, src); ok {
			s.hint(src, 'm', h)
		}
	})
}

func (s *Sources) runSSDP(ctx context.Context) error {
	p, c, err := s.multicast(ctx, 1900, net.IPv4(239, 255, 255, 250))
	if err != nil {
		return err
	}
	defer c.Close()
	return s.readLAN(ctx, p, func(b []byte, src netip.Addr) {
		if v, ok := ParseSSDP(b); ok {
			s.hint(src, 's', model.DeviceHints{SSDPServer: v})
		}
	})
}

// runProbe — по одному короткому запросу имени к новому устройству, по
// очереди: не больше запроса в секунду.
func (s *Sources) runProbe(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case a := <-s.probe:
			if h, ok := s.queryName(ctx, a); ok {
				if mac, ok := s.macOf(a); ok {
					s.opts.Observe(Observation{MAC: mac, IP: a, Hints: h, At: time.Now()})
				}
			}
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(time.Second):
			}
		}
	}
}

func (s *Sources) queryName(ctx context.Context, a netip.Addr) (model.DeviceHints, bool) {
	q, err := ReverseQuery(a, uint16(rand.Uint32()))
	if err != nil {
		return model.DeviceHints{}, false
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp4", netip.AddrPortFrom(a, 5353).String())
	if err != nil {
		return model.DeviceHints{}, false
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write(q); err != nil {
		return model.DeviceHints{}, false
	}
	buf := make([]byte, 9000)
	n, err := c.Read(buf)
	if err != nil {
		return model.DeviceHints{}, false
	}
	return ParseMDNS(buf[:n], a)
}
