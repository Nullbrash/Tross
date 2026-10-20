package resolver

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// maxInflight — одновременных запросов по UDP: всплеск (сотни устройств
// после обрыва канала) не плодит горутины без предела.
const maxInflight = 256

// Serve — слушать адреса до отмены ctx. ready закрывается, когда все
// слушатели открыты (перехват DNS переключается на резолвер только после).
func (r *Resolver) Serve(ctx context.Context, listen []netip.AddrPort, ready chan<- struct{}) error {
	var lc net.ListenConfig
	var pcs []net.PacketConn
	var lns []net.Listener
	closeAll := func() {
		for _, pc := range pcs {
			pc.Close()
		}
		for _, l := range lns {
			l.Close()
		}
	}
	for _, a := range listen {
		pc, err := lc.ListenPacket(ctx, "udp4", a.String())
		if err != nil {
			closeAll()
			return err
		}
		pcs = append(pcs, pc)
		l, err := lc.Listen(ctx, "tcp4", a.String())
		if err != nil {
			closeAll()
			return err
		}
		lns = append(lns, l)
	}
	if ready != nil {
		close(ready)
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxInflight)
	for _, pc := range pcs {
		wg.Go(func() { r.serveUDP(ctx, pc, sem) })
	}
	for _, l := range lns {
		wg.Go(func() { r.serveTCP(ctx, l) })
	}
	<-ctx.Done()
	closeAll()
	wg.Wait()
	return nil
}

func (r *Resolver) serveUDP(ctx context.Context, pc net.PacketConn, sem chan struct{}) {
	buf := make([]byte, 65535)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		ua, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		client := ua.AddrPort().Addr().Unmap()
		if !r.fromHome(client) {
			continue
		}
		q := append([]byte(nil), buf[:n]...)
		select {
		case sem <- struct{}{}:
		default:
			// Перегрузка: молчание — клиент повторит; SERVFAIL закэшировали бы.
			continue
		}
		go func() {
			defer func() { <-sem }()
			if resp := r.Handle(ctx, q, client, 512); resp != nil {
				_, _ = pc.WriteTo(resp, addr)
			}
		}()
	}
}

func (r *Resolver) serveTCP(ctx context.Context, l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if ta, ok := c.RemoteAddr().(*net.TCPAddr); !ok || !r.fromHome(ta.AddrPort().Addr().Unmap()) {
			c.Close()
			continue
		}
		go r.serveConn(ctx, c)
	}
}

// fromHome — запрос из дома (или с самого мини-ПК). Чужому — молчание: не
// открытый резолвер и не признак машины (снаружи и так отбрасывает ядро —
// это запасная линия). Без списка сетей дома — отвечать всем (тесты).
func (r *Resolver) fromHome(a netip.Addr) bool {
	if len(r.cfg.Home) == 0 || a.IsLoopback() {
		return true
	}
	return slices.ContainsFunc(r.cfg.Home, func(p netip.Prefix) bool { return p.Contains(a) })
}

func (r *Resolver) serveConn(ctx context.Context, c net.Conn) {
	defer c.Close()
	ta, _ := c.RemoteAddr().(*net.TCPAddr)
	var client netip.Addr
	if ta != nil {
		client = ta.AddrPort().Addr().Unmap()
	}
	for {
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		var l [2]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		q := make([]byte, binary.BigEndian.Uint16(l[:]))
		if _, err := io.ReadFull(c, q); err != nil {
			return
		}
		resp := r.Handle(ctx, q, client, 0)
		if resp == nil {
			return
		}
		out := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(out, uint16(len(resp)))
		copy(out[2:], resp)
		if _, err := c.Write(out); err != nil {
			return
		}
	}
}

// selfCheckName — имя самопроверки: домашняя зона, наружу не уходит.
const selfCheckName = "tross-selfcheck.internal"

// SelfCheck — отвечает ли слушатель (для сторожа): запрос по UDP к себе.
func SelfCheck(ctx context.Context, addr netip.AddrPort) error {
	q, err := buildQuery(randomID(), selfCheckName, dnsmessage.TypeA, false)
	if err != nil {
		return err
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp4", addr.String())
	if err != nil {
		return err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if _, err := c.Write(q); err != nil {
		return err
	}
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil {
		return err
	}
	if n < 12 || binary.BigEndian.Uint16(buf) != binary.BigEndian.Uint16(q) {
		return errors.New("selfcheck: bad reply")
	}
	return nil
}
