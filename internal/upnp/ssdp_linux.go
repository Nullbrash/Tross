//go:build linux

package upnp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

var ssdpGroup = &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: PortSSDP}

// ServeSSDP — ответы на поиск и анонсы шлюза в группе SSDP на интерфейсе
// LAN; запросы не с LAN — без ответа.
func (g *IGD) ServeSSDP(ctx context.Context, iface string, inLAN func(netip.Addr) bool, log *slog.Logger) error {
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			// Порт 1900 держит и прослушивание реестра (и, может быть, avahi):
			// копию пакета группы получает каждый сокет.
			if serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); serr == nil {
				serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			}
		})
		if err != nil {
			return err
		}
		return serr
	}}
	c, err := lc.ListenPacket(ctx, "udp4", fmt.Sprintf("0.0.0.0:%d", PortSSDP))
	if err != nil {
		return err
	}
	defer c.Close()
	p := ipv4.NewPacketConn(c)
	if err := p.JoinGroup(ifc, ssdpGroup); err != nil {
		return err
	}
	_ = p.SetControlMessage(ipv4.FlagInterface, true)
	_ = p.SetMulticastInterface(ifc)
	_ = p.SetMulticastTTL(2)
	notify := func(alive bool) {
		for _, m := range g.Notifies(alive) {
			_, _ = p.WriteTo(m, nil, ssdpGroup)
		}
	}
	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Go(func() {
		notify(true)
		t := time.NewTicker(15 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				notify(false)
				c.Close()
				return
			case <-t.C:
				notify(true)
			}
		}
	})
	last := map[netip.AddrPort]time.Time{}
	buf := make([]byte, 4096)
	for {
		n, cm, from, err := p.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		ua, ok := from.(*net.UDPAddr)
		if !ok || cm == nil || cm.IfIndex != ifc.Index {
			continue
		}
		src, ok := netip.AddrFromSlice(ua.IP.To4())
		if !ok || !inLAN(src) {
			continue
		}
		replies := g.SearchReplies(buf[:n])
		if replies == nil {
			continue
		}
		// Поиск шлют пачками (повтор того же запроса) — одному сокету
		// клиента ответ не чаще раза в 100 мс.
		from4 := netip.AddrPortFrom(src, uint16(ua.Port))
		if now := time.Now(); now.Sub(last[from4]) < 100*time.Millisecond {
			continue
		} else {
			if len(last) > 1024 {
				clear(last)
			}
			last[from4] = now
		}
		for _, r := range replies {
			if _, err := p.WriteTo(r, nil, ua); err != nil {
				log.Debug("upnp: ssdp reply", "to", ua, "err", err)
			}
		}
	}
}
