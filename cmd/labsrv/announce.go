package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// announce — «устройство» стенда рассказывает о себе так, как это делают
// телефоны, ТВ и ПК: запрос DHCP (широковещательно, с порта 68), анонс
// mDNS, анонс SSDP.
//
//	labsrv announce -dhcp -mac a6:00:00:00:00:77 -hostname Galaxy-S23 -vendor android-dhcp-14 -params 1,3,6,15
//	labsrv announce -mdns Kitchen-TV -addr 192.168.77.10 [-model MacBookPro18,3]
//	labsrv announce -ssdp "Linux/4.4 UPnP/1.0 webOS/1.0"
func announce(args []string) error {
	fs := flag.NewFlagSet("announce", flag.ExitOnError)
	dhcp := fs.Bool("dhcp", false, "send a DHCPDISCOVER")
	mac := fs.String("mac", "", "client MAC in the DHCP message")
	hostname := fs.String("hostname", "", "DHCP option 12")
	vendor := fs.String("vendor", "", "DHCP option 60")
	params := fs.String("params", "1,3,6,15", "DHCP option 55, comma separated")
	mdns := fs.String("mdns", "", "announce this host name over mDNS")
	addr := fs.String("addr", "", "address for the mDNS A record")
	model := fs.String("model", "", "model= in _device-info")
	ssdp := fs.String("ssdp", "", "send an SSDP NOTIFY with this SERVER header")
	count := fs.Int("count", 1, "how many times (mDNS, SSDP)")
	every := fs.Duration("every", 0, "pause between repeats")
	_ = fs.Parse(args)
	if *count > 1 && !*dhcp {
		for i := range *count {
			if err := announceOnce(*mdns, *addr, *model, *ssdp); err != nil {
				return fmt.Errorf("announce %d: %w", i, err)
			}
			time.Sleep(*every)
		}
		return nil
	}
	switch {
	case *dhcp:
		return announceDHCP(*mac, *hostname, *vendor, *params)
	case *mdns != "":
		return announceMDNS(*mdns, *addr, *model)
	case *ssdp != "":
		return announceOnce("", "", "", *ssdp)
	}
	return errors.New("announce: want -dhcp, -mdns or -ssdp")
}

func announceOnce(mdns, addr, model, ssdp string) error {
	if mdns != "" {
		return announceMDNS(mdns, addr, model)
	}
	msg := "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nCACHE-CONTROL: max-age=1800\r\nNT: upnp:rootdevice\r\nNTS: ssdp:alive\r\nSERVER: " + ssdp + "\r\nUSN: uuid:lab::upnp:rootdevice\r\n\r\n"
	return sendUDP("239.255.255.250:1900", []byte(msg), 0)
}

func announceDHCP(macS, hostname, vendor, params string) error {
	hw, err := net.ParseMAC(macS)
	if err != nil || len(hw) != 6 {
		return fmt.Errorf("announce: -mac: %v", err)
	}
	b := make([]byte, 240)
	b[0], b[1], b[2] = 1, 1, 6
	binary.BigEndian.PutUint32(b[4:8], uint32(time.Now().UnixNano()))
	binary.BigEndian.PutUint16(b[10:12], 0x8000) // ответ — широковещательно
	copy(b[28:34], hw)
	binary.BigEndian.PutUint32(b[236:240], 0x63825363)
	opt := func(code byte, v []byte) { b = append(append(b, code, byte(len(v))), v...) }
	opt(53, []byte{1})
	if hostname != "" {
		opt(12, []byte(hostname))
	}
	if vendor != "" {
		opt(60, []byte(vendor))
	}
	opt(61, append([]byte{1}, hw...))
	var ps []byte
	for _, p := range strings.Split(params, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || n < 1 || n > 254 {
			return fmt.Errorf("announce: -params: %q", p)
		}
		ps = append(ps, byte(n))
	}
	opt(55, ps)
	b = append(b, 255)
	return sendUDP("255.255.255.255:67", b, 68)
}

func announceMDNS(host, addrS, model string) error {
	a, err := netip.ParseAddr(addrS)
	if err != nil || !a.Is4() {
		return fmt.Errorf("announce: -addr: %q", addrS)
	}
	name := host + ".local."
	res := []dnsmessage.Resource{{
		Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 120},
		Body:   &dnsmessage.AResource{A: a.As4()},
	}}
	if model != "" {
		res = append(res, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(host + "._device-info._tcp.local."), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 4500},
			Body:   &dnsmessage.TXTResource{TXT: []string{"model=" + model}},
		})
	}
	m := dnsmessage.Message{Header: dnsmessage.Header{Response: true, Authoritative: true}, Answers: res}
	b, err := m.Pack()
	if err != nil {
		return err
	}
	return sendUDP("224.0.0.251:5353", b, 0)
}

// sendUDP — один датаграм; from — порт отправителя (0 — любой).
func sendUDP(to string, b []byte, from int) error {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{Port: from})
	if err != nil {
		return err
	}
	defer c.Close()
	dst, err := net.ResolveUDPAddr("udp4", to)
	if err != nil {
		return err
	}
	_, err = c.WriteToUDP(b, dst)
	return err
}

// mdnsd — отвечает на запрос mDNS «имя по адресу» (обратная PTR), как
// телефон или ПК с Bonjour/avahi; работает -duration.
//
//	labsrv mdnsd -name lab-client -addr 192.168.77.10 -duration 30s
func mdnsd(args []string) error {
	fs := flag.NewFlagSet("mdnsd", flag.ExitOnError)
	host := fs.String("name", "", "host name to answer with")
	addrS := fs.String("addr", "", "own address")
	dur := fs.Duration("duration", 30*time.Second, "how long to answer")
	_ = fs.Parse(args)
	a, err := netip.ParseAddr(*addrS)
	if err != nil || !a.Is4() || *host == "" {
		return errors.New("mdnsd: want -name and an IPv4 -addr")
	}
	b4 := a.As4()
	rev := fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", b4[3], b4[2], b4[1], b4[0])
	c, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 5353})
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(*dur))
	buf := make([]byte, 9000)
	for {
		n, src, err := c.ReadFromUDP(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return nil
			}
			return err
		}
		var m dnsmessage.Message
		if m.Unpack(buf[:n]) != nil || m.Response || len(m.Questions) == 0 {
			continue
		}
		q := m.Questions[0]
		if q.Type != dnsmessage.TypePTR || !strings.EqualFold(q.Name.String(), rev) {
			continue
		}
		resp := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: m.ID, Response: true, Authoritative: true},
			Questions: m.Questions,
			Answers: []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET, TTL: 120},
				Body:   &dnsmessage.PTRResource{PTR: dnsmessage.MustNewName(*host + ".local.")},
			}},
		}
		out, err := resp.Pack()
		if err != nil {
			return err
		}
		if _, err := c.WriteToUDP(out, src); err != nil {
			log.Printf("mdnsd: reply to %s: %v", src, err)
		}
	}
}

// dhcpMsg — сообщение клиента DHCP с chaddr hw; extra — опции «код, значение».
func dhcpMsg(typ byte, hw net.HardwareAddr, xid uint32, hostname string, extra ...[]byte) []byte {
	b := make([]byte, 240)
	b[0], b[1], b[2] = 1, 1, 6
	binary.BigEndian.PutUint32(b[4:8], xid)
	binary.BigEndian.PutUint16(b[10:12], 0x8000)
	copy(b[28:34], hw)
	binary.BigEndian.PutUint32(b[236:240], 0x63825363)
	b = append(b, 53, 1, typ)
	if hostname != "" {
		b = append(append(b, 12, byte(len(hostname))), hostname...)
	}
	b = append(append(b, 61, 7, 1), hw...)
	b = append(b, 55, 3, 1, 3, 6)
	for _, o := range extra {
		b = append(b, o...)
	}
	return append(b, 255)
}

// dhcpReply — ответ сервера с xid: тип, выданный адрес, идентификатор сервера.
func dhcpReply(c *net.UDPConn, xid uint32, deadline time.Time) (typ byte, yi, server netip.Addr, err error) {
	_ = c.SetReadDeadline(deadline)
	buf := make([]byte, 1500)
	for {
		n, _, err := c.ReadFromUDP(buf)
		if err != nil {
			return 0, yi, server, err
		}
		b := buf[:n]
		if n < 240 || b[0] != 2 || binary.BigEndian.Uint32(b[4:8]) != xid {
			continue
		}
		yi = netip.AddrFrom4([4]byte(b[16:20]))
		for i := 240; i+1 < n && b[i] != 255; {
			if b[i] == 0 {
				i++
				continue
			}
			l := int(b[i+1])
			if i+2+l > n {
				break
			}
			switch v := b[i+2 : i+2+l]; b[i] {
			case 53:
				typ = v[0]
			case 54:
				if l == 4 {
					server = netip.AddrFrom4([4]byte(v))
				}
			}
			i += 2 + l
		}
		return typ, yi, server, nil
	}
}

// dhcpc — клиент DHCP с любым MAC: обмен целиком, печатает выданный адрес.
//
//	labsrv dhcpc -mac a6:00:00:00:00:01 -hostname Galaxy-Lab
func dhcpc(args []string) error {
	fs := flag.NewFlagSet("dhcpc", flag.ExitOnError)
	macS := fs.String("mac", "", "client MAC")
	hostname := fs.String("hostname", "", "DHCP option 12")
	timeout := fs.Duration("timeout", 5*time.Second, "per step")
	_ = fs.Parse(args)
	hw, err := net.ParseMAC(*macS)
	if err != nil || len(hw) != 6 {
		return fmt.Errorf("dhcpc: -mac: %v", err)
	}
	c, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 68})
	if err != nil {
		return err
	}
	defer c.Close()
	bcast := &net.UDPAddr{IP: net.IPv4bcast, Port: 67}
	xid := uint32(time.Now().UnixNano())
	if _, err := c.WriteToUDP(dhcpMsg(1, hw, xid, *hostname), bcast); err != nil {
		return err
	}
	typ, offered, server, err := dhcpReply(c, xid, time.Now().Add(*timeout))
	if err != nil || typ != 2 {
		return fmt.Errorf("dhcpc: no offer: type %d, %v", typ, err)
	}
	req := dhcpMsg(3, hw, xid, *hostname, append([]byte{50, 4}, offered.AsSlice()...), append([]byte{54, 4}, server.AsSlice()...))
	if _, err := c.WriteToUDP(req, bcast); err != nil {
		return err
	}
	typ, got, _, err := dhcpReply(c, xid, time.Now().Add(*timeout))
	if err != nil || typ != 5 {
		return fmt.Errorf("dhcpc: no ack: type %d, %v", typ, err)
	}
	fmt.Printf("%s %s\n", got, server)
	return nil
}
