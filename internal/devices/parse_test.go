package devices

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"tross/core/model"
)

// dhcpPacket — сообщение DHCP с chaddr mac, ciaddr/yiaddr и опциями.
func dhcpPacket(mac model.MAC, ci, yi string, opts ...[]byte) []byte {
	b := make([]byte, 240)
	b[0], b[1], b[2] = 1, 1, 6
	copy(b[12:16], netip.MustParseAddr(ci).AsSlice())
	copy(b[16:20], netip.MustParseAddr(yi).AsSlice())
	copy(b[28:34], mac[:])
	binary.BigEndian.PutUint32(b[236:240], 0x63825363)
	for _, o := range opts {
		b = append(b, o...)
	}
	return append(b, 255)
}

func opt(code byte, v ...byte) []byte { return append([]byte{code, byte(len(v))}, v...) }

func TestParseDHCPRequest(t *testing.T) {
	mac := model.MAC{0xa6, 1, 2, 3, 4, 5}
	b := dhcpPacket(mac, "0.0.0.0", "0.0.0.0",
		opt(53, dhcpRequest),
		opt(12, []byte("Galaxy-S23\x00\x07")...), // управляющие символы вырезаются
		opt(60, []byte("android-dhcp-14")...),
		opt(61, 1, 0xa6, 1, 2, 3, 4, 5),
		opt(55, 1, 3, 6, 15, 26, 28, 51, 58, 59, 43),
		[]byte{0, 0}, // заполнители
	)
	d, err := ParseDHCP(b)
	if err != nil {
		t.Fatal(err)
	}
	want := model.DeviceHints{DHCPHostname: "Galaxy-S23", DHCPVendorClass: "android-dhcp-14", DHCPClientID: "01a60102030405", DHCPParams: "1,3,6,15,26,28,51,58,59,43"}
	if d.Type != dhcpRequest || d.MAC != mac || d.Hints != want {
		t.Fatalf("parsed %+v", d)
	}
	o, ok := d.Observation(time.Unix(1, 0))
	if !ok || o.IP.IsValid() || o.Hints != want {
		t.Fatalf("observation %+v %v", o, ok)
	}
}

func TestParseDHCPAckAndRenew(t *testing.T) {
	mac := model.MAC{0, 3, 0x93, 1, 2, 3}
	ack, err := ParseDHCP(dhcpPacket(mac, "0.0.0.0", "192.168.10.50", opt(53, dhcpAck), opt(12, 'x')))
	if err != nil {
		t.Fatal(err)
	}
	o, ok := ack.Observation(time.Unix(1, 0))
	// В подтверждении — опции сервера: подсказками устройства они не являются.
	if !ok || o.IP != netip.MustParseAddr("192.168.10.50") || o.Hints != (model.DeviceHints{}) {
		t.Fatalf("ack observation %+v %v", o, ok)
	}
	renew, _ := ParseDHCP(dhcpPacket(mac, "192.168.10.50", "0.0.0.0", opt(53, dhcpRequest)))
	if o, ok := renew.Observation(time.Unix(1, 0)); !ok || o.IP != netip.MustParseAddr("192.168.10.50") {
		t.Fatalf("renew observation %+v %v", o, ok)
	}
	rel, _ := ParseDHCP(dhcpPacket(mac, "192.168.10.50", "0.0.0.0", opt(53, 7)))
	if _, ok := rel.Observation(time.Unix(1, 0)); ok {
		t.Error("RELEASE must not count as activity")
	}
}

func TestParseDHCPRejectsJunk(t *testing.T) {
	mac := model.MAC{0, 3, 0x93, 1, 2, 3}
	good := dhcpPacket(mac, "0.0.0.0", "0.0.0.0", opt(53, dhcpDiscover))
	cases := map[string][]byte{
		"short":       good[:100],
		"no magic":    append(append([]byte{}, good[:236]...), 0, 0, 0, 0, 255),
		"truncated":   append(good[:len(good)-1], 12, 40, 'a'),
		"no msg type": dhcpPacket(mac, "0.0.0.0", "0.0.0.0", opt(12, 'a')),
	}
	for name, b := range cases {
		if _, err := ParseDHCP(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	long := strings.Repeat("ж", 100)
	d, err := ParseDHCP(dhcpPacket(mac, "0.0.0.0", "0.0.0.0", opt(53, dhcpDiscover), opt(12, []byte(long[:200])...)))
	if err != nil || len([]rune(d.Hints.DHCPHostname)) != maxHint {
		t.Errorf("long hostname: %q %v", d.Hints.DHCPHostname, err)
	}
}

func mdnsResponse(t *testing.T, res ...dnsmessage.Resource) []byte {
	t.Helper()
	m := dnsmessage.Message{Header: dnsmessage.Header{Response: true, Authoritative: true}, Answers: res[:1], Additionals: res[1:]}
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func rhdr(name string, typ dnsmessage.Type) dnsmessage.ResourceHeader {
	return dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET, TTL: 120}
}

func TestParseMDNS(t *testing.T) {
	src := netip.MustParseAddr("192.168.10.40")
	b := mdnsResponse(t,
		dnsmessage.Resource{Header: rhdr("Other.local.", dnsmessage.TypeA), Body: &dnsmessage.AResource{A: [4]byte{192, 168, 10, 99}}},
		dnsmessage.Resource{Header: rhdr("Owners-MacBook.local.", dnsmessage.TypeA), Body: &dnsmessage.AResource{A: src.As4()}},
		dnsmessage.Resource{Header: rhdr("Owners-MacBook._device-info._tcp.local.", dnsmessage.TypeTXT), Body: &dnsmessage.TXTResource{TXT: []string{"model=MacBookPro18,3", "osxvers=24"}}},
		dnsmessage.Resource{Header: rhdr("x.local.", dnsmessage.TypeAAAA), Body: &dnsmessage.AAAAResource{}},
	)
	h, ok := ParseMDNS(b, src)
	if !ok || h.MDNSName != "Owners-MacBook" || h.MDNSModel != "MacBookPro18,3" {
		t.Fatalf("hints %+v %v", h, ok)
	}
	// Чужой адрес в записи A — не имя отправителя.
	if h, _ := ParseMDNS(b, netip.MustParseAddr("192.168.10.41")); h.MDNSName != "" {
		t.Errorf("name of another address: %+v", h)
	}
	// Ответ на обратный запрос.
	rev := mdnsResponse(t, dnsmessage.Resource{Header: rhdr("40.10.168.192.in-addr.arpa.", dnsmessage.TypePTR), Body: &dnsmessage.PTRResource{PTR: dnsmessage.MustNewName("Kitchen-TV.local.")}})
	if h, ok := ParseMDNS(rev, src); !ok || h.MDNSName != "Kitchen-TV" {
		t.Errorf("reverse: %+v %v", h, ok)
	}
	q, err := ReverseQuery(src, 7)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ParseMDNS(q, src); ok {
		t.Error("a query is not an announcement")
	}
	if _, ok := ParseMDNS([]byte{1, 2, 3}, src); ok {
		t.Error("junk accepted")
	}
}

func TestParseSSDP(t *testing.T) {
	notify := "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nServer: Linux/4.4 UPnP/1.0 webOS/1.0\r\nNTS: ssdp:alive\r\n\r\n"
	if s, ok := ParseSSDP([]byte(notify)); !ok || s != "Linux/4.4 UPnP/1.0 webOS/1.0" {
		t.Errorf("notify: %q %v", s, ok)
	}
	if _, ok := ParseSSDP([]byte("M-SEARCH * HTTP/1.1\r\nSERVER: x\r\n\r\n")); ok {
		t.Error("search request is not an announcement")
	}
	if _, ok := ParseSSDP([]byte("NOTIFY * HTTP/1.1\r\nNTS: ssdp:byebye\r\n\r\n")); ok {
		t.Error("no SERVER header")
	}
}
