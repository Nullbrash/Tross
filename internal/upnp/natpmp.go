package upnp

import (
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"time"

	"tross/core/model"
	coreupnp "tross/core/upnp"
	"tross/internal/dataplane"
)

// Mapper — что протоколам нужно от службы.
type Mapper interface {
	Map(ctx context.Context, r coreupnp.Request) (coreupnp.Decision, error)
	Unmap(ctx context.Context, src netip.Addr, proto model.Protocol, port uint16) error
	Owned(ctx context.Context, src netip.Addr) ([]dataplane.UPnPMapping, error)
	ExternalIP() netip.Addr
	Epoch() uint32
}

// PortNATPMP — порт NAT-PMP и PCP (RFC 6886, RFC 6887).
const PortNATPMP = 5351

// Коды NAT-PMP.
const (
	pmpOK             = 0
	pmpBadVersion     = 1
	pmpNotAuthorized  = 2
	pmpNetworkFailure = 3
	pmpNoResources    = 4
	pmpBadOpcode      = 5
)

// Коды PCP.
const (
	pcpOK            = 0
	pcpBadVersion    = 1
	pcpNotAuthorized = 2
	pcpMalformed     = 3
	pcpBadOpcode     = 4
	pcpBadOption     = 5
	pcpNetFailure    = 7
	pcpNoResources   = 8
	pcpBadProto      = 9
	pcpCannotExt     = 11
	pcpAddrMismatch  = 12
	// pcpErrorLife — сколько клиенту не повторять запрос после ошибки.
	pcpErrorLife = 30
)

func pmpResult(d coreupnp.Decision, err error) uint16 {
	switch {
	case err != nil:
		return pmpNetworkFailure
	case d.Outcome == coreupnp.Allow:
		return pmpOK
	case d.Reason == coreupnp.NoResources || d.Reason == coreupnp.Conflict:
		return pmpNoResources
	}
	return pmpNotAuthorized
}

// HandlePMP — ответ на пакет NAT-PMP или PCP с адреса src; nil — не
// отвечать (ответ сервера, мусор).
func HandlePMP(ctx context.Context, m Mapper, b []byte, src netip.Addr) []byte {
	if len(b) < 2 || len(b) > 1100 {
		return nil
	}
	switch b[0] {
	case 0:
		return handleNATPMP(ctx, m, b, src)
	case 2:
		return handlePCP(ctx, m, b, src)
	case 1:
		// Версия 1 — черновик PCP: отвечаем как PCP «неподдерживаемая версия».
		return pcpHeader(b[1]&0x7f, pcpBadVersion, pcpErrorLife, m.Epoch())
	}
	return nil
}

func handleNATPMP(ctx context.Context, m Mapper, b []byte, src netip.Addr) []byte {
	op := b[1]
	if op >= 128 {
		return nil
	}
	head := func(result uint16, n int) []byte {
		r := make([]byte, n)
		r[1] = 128 + op
		binary.BigEndian.PutUint16(r[2:4], result)
		binary.BigEndian.PutUint32(r[4:8], m.Epoch())
		return r
	}
	switch op {
	case 0:
		r := head(pmpOK, 12)
		ext := m.ExternalIP().As4()
		copy(r[8:12], ext[:])
		return r
	case 1, 2:
		if len(b) < 12 {
			return nil
		}
		proto := model.ProtoUDP
		if op == 2 {
			proto = model.ProtoTCP
		}
		in, sugg := binary.BigEndian.Uint16(b[4:6]), binary.BigEndian.Uint16(b[6:8])
		life := binary.BigEndian.Uint32(b[8:12])
		r := head(pmpOK, 16)
		binary.BigEndian.PutUint16(r[8:10], in)
		owned, err := m.Owned(ctx, src)
		if err != nil {
			binary.BigEndian.PutUint16(r[2:4], pmpNetworkFailure)
			return r
		}
		if life == 0 {
			for _, x := range owned {
				if x.Proto == proto && (x.IntPort == in || in == 0 && sugg == 0) {
					_ = m.Unmap(ctx, src, proto, x.ExtPort)
				}
			}
			return r
		}
		// Продление: клиент мог забыть выданный порт — берём его проброс.
		if i := slices.IndexFunc(owned, func(x dataplane.UPnPMapping) bool { return x.Proto == proto && x.IntPort == in }); i >= 0 && sugg == 0 {
			sugg = owned[i].ExtPort
		}
		d, err := m.Map(ctx, coreupnp.Request{Via: coreupnp.ViaNATPMP, Proto: proto, ExtPort: sugg, IntPort: in, Client: src, Source: src,
			Lease: time.Duration(life) * time.Second, AnyPort: true})
		binary.BigEndian.PutUint16(r[2:4], pmpResult(d, err))
		if err == nil && d.Outcome == coreupnp.Allow {
			binary.BigEndian.PutUint16(r[10:12], d.ExtPort)
			binary.BigEndian.PutUint32(r[12:16], uint32(d.Lease/time.Second))
		}
		return r
	}
	return head(pmpBadOpcode, 8)
}

func pcpHeader(op, result byte, life, epoch uint32) []byte {
	r := make([]byte, 24)
	r[0], r[1], r[3] = 2, 0x80|op, result
	binary.BigEndian.PutUint32(r[4:8], life)
	binary.BigEndian.PutUint32(r[8:12], epoch)
	return r
}

func mapped(a netip.Addr) [16]byte { return netip.AddrFrom16(a.As16()).As16() }

func handlePCP(ctx context.Context, m Mapper, b []byte, src netip.Addr) []byte {
	if b[1]&0x80 != 0 {
		return nil
	}
	op := b[1] & 0x7f
	if len(b) < 24 || len(b)%4 != 0 {
		return pcpHeader(op, pcpMalformed, pcpErrorLife, m.Epoch())
	}
	life := binary.BigEndian.Uint32(b[4:8])
	if client := netip.AddrFrom16([16]byte(b[8:24])).Unmap(); client != src {
		return pcpHeader(op, pcpAddrMismatch, pcpErrorLife, m.Epoch())
	}
	switch op {
	case 0: // ANNOUNCE
		return pcpHeader(op, pcpOK, 0, m.Epoch())
	case 1: // MAP
	default:
		return pcpHeader(op, pcpBadOpcode, pcpErrorLife, m.Epoch())
	}
	if len(b) < 60 {
		return pcpHeader(op, pcpMalformed, pcpErrorLife, m.Epoch())
	}
	body := b[24:60]
	reply := func(result byte, life uint32, ext uint16, extIP netip.Addr) []byte {
		r := append(pcpHeader(op, result, life, m.Epoch()), make([]byte, 36)...)
		copy(r[24:36], body[0:12]) // nonce
		r[36] = body[12]
		copy(r[40:42], body[16:18])
		binary.BigEndian.PutUint16(r[42:44], ext)
		ip := mapped(extIP)
		copy(r[44:60], ip[:])
		return r
	}
	preferFailure := false
	for o := b[60:]; len(o) > 0; {
		if len(o) < 4 {
			return reply(pcpMalformed, pcpErrorLife, 0, netip.IPv6Unspecified())
		}
		code, n := o[0], int(binary.BigEndian.Uint16(o[2:4]))
		pad := 4 + (n+3)/4*4
		if pad > len(o) {
			return reply(pcpMalformed, pcpErrorLife, 0, netip.IPv6Unspecified())
		}
		switch {
		case code == 2: // PREFER_FAILURE
			preferFailure = true
		case code == 1: // THIRD_PARTY — проброс на чужой адрес
			return reply(pcpNotAuthorized, pcpErrorLife, 0, netip.IPv6Unspecified())
		case code < 128: // обязательная, нам неизвестная (FILTER и др.)
			return reply(pcpBadOption, pcpErrorLife, 0, netip.IPv6Unspecified())
		}
		o = o[pad:]
	}
	var proto model.Protocol
	switch body[12] {
	case 6:
		proto = model.ProtoTCP
	case 17:
		proto = model.ProtoUDP
	default:
		return reply(pcpBadProto, pcpErrorLife, 0, netip.IPv6Unspecified())
	}
	in, sugg := binary.BigEndian.Uint16(body[16:18]), binary.BigEndian.Uint16(body[18:20])
	if in == 0 {
		return reply(pcpMalformed, pcpErrorLife, 0, netip.IPv6Unspecified())
	}
	if life == 0 {
		owned, err := m.Owned(ctx, src)
		if err != nil {
			return reply(pcpNetFailure, pcpErrorLife, 0, netip.IPv6Unspecified())
		}
		for _, x := range owned {
			if x.Proto == proto && x.IntPort == in {
				_ = m.Unmap(ctx, src, proto, x.ExtPort)
			}
		}
		return reply(pcpOK, 0, sugg, m.ExternalIP())
	}
	d, err := m.Map(ctx, coreupnp.Request{Via: coreupnp.ViaPCP, Proto: proto, ExtPort: sugg, IntPort: in, Client: src, Source: src,
		Lease: time.Duration(life) * time.Second, AnyPort: !preferFailure})
	switch {
	case err != nil:
		return reply(pcpNetFailure, pcpErrorLife, 0, netip.IPv6Unspecified())
	case d.Outcome == coreupnp.Allow:
		return reply(pcpOK, uint32(d.Lease/time.Second), d.ExtPort, m.ExternalIP())
	case d.Reason == coreupnp.NoResources:
		return reply(pcpNoResources, pcpErrorLife, 0, netip.IPv6Unspecified())
	case d.Reason == coreupnp.Conflict:
		return reply(pcpCannotExt, pcpErrorLife, 0, netip.IPv6Unspecified())
	}
	return reply(pcpNotAuthorized, pcpErrorLife, 0, netip.IPv6Unspecified())
}

// ServePMP — NAT-PMP и PCP на адресе LAN; запросы не из LAN — без ответа
// (со стороны каналов порт закрыт и правилом ядра).
func ServePMP(ctx context.Context, m Mapper, lan netip.Addr, inLAN func(netip.Addr) bool, log *slog.Logger) error {
	c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(lan, PortNATPMP)))
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		c.Close()
	}()
	buf := make([]byte, 1100)
	for {
		n, from, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		src := from.Addr().Unmap()
		if !inLAN(src) {
			continue
		}
		if r := HandlePMP(ctx, m, buf[:n], src); r != nil {
			if _, err := c.WriteToUDPAddrPort(r, from); err != nil {
				log.Debug("upnp: nat-pmp reply", "to", from, "err", err)
			}
		}
	}
}
