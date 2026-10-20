package dataplane

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"tross/core/model"
)

func TestRenderUPnP(t *testing.T) {
	spec := testSpec()
	spec.UPnP = UPnPSpec{Enabled: true, Links: []int{0, 1}, UDPPorts: []uint16{1900, 5351}, TCPPorts: []uint16{5000}}
	if err := validateUPnP(spec); err != nil {
		t.Fatal(err)
	}
	got := renderUPnP(spec)
	for _, want := range []string{
		// Объекты — add (пробросы в отображении переживают пересборку),
		// цепочки — заново.
		"add map inet tross_upnp portmap { type inet_proto . inet_service : ipv4_addr . inet_service; flags timeout; }",
		"flush chain inet tross_upnp natpre",
		`add rule inet tross_upnp natpre iifname { "wan1", "wan2" } dnat ip to meta l4proto . th dport map @portmap`,
		`add rule inet tross_upnp guard iifname { "wan1", "wan2" } ct state new meta l4proto . th dport @ports jump inbound`,
		`add rule inet tross_upnp markpre iifname "wan2" ct state new meta l4proto . th dport @ports meta mark set 0x200 ct mark set 0x200`,
		// Службы UPnP мини-ПК со стороны всех каналов (и LTE) закрыты.
		`add rule inet tross_upnp svcin iifname { "wan1", "wan2", "wan3" } udp dport { 1900, 5351 } counter drop`,
		`add rule inet tross_upnp svcin iifname { "wan1", "wan2", "wan3" } tcp dport { 5000 } counter drop`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "delete table") {
		t.Error("enabled table must not be replaced")
	}
	spec.UPnP.Enabled = false
	if got := renderUPnP(spec); !strings.Contains(got, "delete table inet tross_upnp") {
		t.Errorf("disabled: %s", got)
	}
	spec.UPnP = UPnPSpec{Enabled: true, Links: []int{7}}
	if validateUPnP(spec) == nil {
		t.Error("bad link index accepted")
	}
	set := renderUPnPSet(UPnPMapping{Proto: model.ProtoTCP, ExtPort: 51413, Addr: netip.MustParseAddr("192.168.10.20"), IntPort: 51413, Lease: time.Hour, Desc: `q"B\it` + "\n"})
	if !strings.Contains(set, `destroy element inet tross_upnp portmap { tcp . 51413 }`) ||
		!strings.Contains(set, `add element inet tross_upnp portmap { tcp . 51413 timeout 3600s comment "qBit" : 192.168.10.20 . 51413 }`) {
		t.Errorf("set:\n%s", set)
	}
}

// Ответ nft -j со стенда (nft 1.1.3).
const upnpJSON = `{"nftables": [{"metainfo": {"version": "1.1.3", "release_name": "Commodore Bullmoose #4", "json_schema_version": 1}}, {"map": {"family": "inet", "name": "portmap", "table": "tross_upnp", "type": ["inet_proto", "inet_service"], "handle": 1, "map": ["ipv4_addr", "inet_service"], "flags": ["timeout"], "elem": [[{"elem": {"val": {"concat": ["udp", 3074]}, "timeout": 3600, "expires": 3599, "comment": ""}}, {"concat": ["192.168.10.30", 3074]}], [{"elem": {"val": {"concat": ["tcp", 51413]}, "timeout": 7200, "expires": 7199, "comment": "TorrentClient"}}, {"concat": ["192.168.10.20", 51413]}]]}}]}`

func TestParseUPnPMap(t *testing.T) {
	ms, err := parseUPnPMap([]byte(upnpJSON))
	if err != nil || len(ms) != 2 {
		t.Fatalf("%+v %v", ms, err)
	}
	if m := ms[0]; m.Proto != model.ProtoTCP || m.ExtPort != 51413 || m.Addr != netip.MustParseAddr("192.168.10.20") || m.Desc != "TorrentClient" || m.Expires != 7199*time.Second {
		t.Errorf("first %+v", m)
	}
	if ms, err := parseUPnPMap([]byte(`{"nftables": [{"map": {"name": "portmap"}}]}`)); err != nil || len(ms) != 0 {
		t.Errorf("empty map: %+v %v", ms, err)
	}
}

func TestFakeUPnPExpires(t *testing.T) {
	ctx := context.Background()
	f := NewFake(slog.New(slog.NewTextHandler(io.Discard, nil)))
	m := UPnPMapping{Proto: model.ProtoUDP, ExtPort: 3074, Addr: netip.MustParseAddr("192.168.10.30"), IntPort: 3074, Lease: time.Second}
	if err := f.SetUPnP(ctx, m); err != nil {
		t.Fatal(err)
	}
	if ms, _ := f.UPnPMappings(ctx); len(ms) != 1 {
		t.Fatalf("%+v", ms)
	}
	f.upnp[upnpKey{m.Proto, m.ExtPort}] = fakeUPnP{m: m, until: time.Now().Add(-time.Second)}
	if ms, _ := f.UPnPMappings(ctx); len(ms) != 0 {
		t.Errorf("expired kept: %+v", ms)
	}
	m.Lease = 0
	if f.SetUPnP(ctx, m) == nil {
		t.Error("zero lease accepted")
	}
}
