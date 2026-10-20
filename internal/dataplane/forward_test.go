package dataplane

import (
	"net/netip"
	"strings"
	"testing"

	"tross/core/model"
	"tross/core/profile"
)

func forwardSpec() Spec {
	spec := testSpec()
	spec.Forwards = []PortForward{
		{Name: "mc", Protos: []model.Protocol{model.ProtoTCP}, Ports: profile.PortRange{From: 25565, To: 25565},
			To: netip.MustParseAddr("192.168.10.50"), Links: []model.LinkID{"isp1", "isp2"}},
		{Name: "game", Protos: []model.Protocol{model.ProtoTCP, model.ProtoUDP}, Ports: profile.PortRange{From: 27015, To: 27030},
			To: netip.MustParseAddr("192.168.10.51")},
		{Name: "ssh", Protos: []model.Protocol{model.ProtoTCP}, Ports: profile.PortRange{From: 2222, To: 2222},
			To: netip.MustParseAddr("192.168.10.52"), ToPort: 22, Links: []model.LinkID{"isp2"}},
	}
	spec.Guard = InboundGuard{NewPerMinute: 20, Burst: 10, MaxConns: 32}
	return spec
}

func TestRenderForwards(t *testing.T) {
	spec := forwardSpec()
	if err := validateForwards(spec); err != nil {
		t.Fatal(err)
	}
	isp1, isp2 := quote(spec.Links[0].Link.Interface), quote(spec.Links[1].Link.Interface)
	nat := renderNAT(spec)
	for _, want := range []string{
		// Только на перечисленных каналах; без links — на всех.
		"iifname { " + isp1 + ", " + isp2 + " } meta l4proto tcp th dport 25565 dnat ip to 192.168.10.50\n",
		"meta l4proto { tcp, udp } th dport 27015-27030 dnat ip to 192.168.10.51\n",
		"iifname { " + isp2 + " } meta l4proto tcp th dport 2222 dnat ip to 192.168.10.52:22\n",
		// Защита — до DNAT, на каждый проброс.
		"type filter hook prerouting priority dstnat - 10; policy accept;\n",
		"iifname { " + isp2 + " } meta l4proto tcp th dport 2222 ct state new jump inbound\n",
		"add @tross_in_rate { ip saddr limit rate over 20/minute burst 10 packets } counter drop\n",
		"add @tross_in_conn { ip saddr ct count over 32 } counter drop\n",
		"masquerade",
	} {
		if !strings.Contains(nat, want) {
			t.Errorf("NAT table lacks:\n%s---\n%s", want, nat)
		}
	}
	if strings.Count(nat, "dnat ip to") != 3 {
		t.Errorf("want 3 DNAT rules:\n%s", nat)
	}
	base := renderBase(spec)
	// Метка канала, через который пришло, — для ответа в тот же канал.
	want := "iifname " + isp2 + " meta l4proto tcp th dport 2222 ct state new meta mark set 0x200 ct mark set 0x200\n"
	if !strings.Contains(base, want) {
		t.Errorf("base lacks:\n%s---\n%s", want, base)
	}
	// Метка — после восстановления: у новых соединений ct mark ещё пуст.
	if strings.Index(base, "meta mark set 0x200 ct mark set 0x200") < strings.Index(base, "meta mark set ct mark and") {
		t.Error("forward marks must follow the mark restore")
	}
	// game на всех трёх каналах: 3 метки; mc — 2; ssh — 1.
	if n := strings.Count(base, "ct state new meta mark set"); n != 6 {
		t.Errorf("want 6 forward mark rules, got %d:\n%s", n, base)
	}
}

func TestNoForwardsNoInboundChains(t *testing.T) {
	spec := testSpec()
	if nat := renderNAT(spec); strings.Contains(nat, "dnat ip to") || strings.Contains(nat, "chain guard") {
		t.Errorf("NAT without forwards:\n%s", nat)
	}
	if err := validateForwards(spec); err != nil {
		t.Errorf("empty forwards need no guard: %v", err)
	}
}

func TestValidateForwards(t *testing.T) {
	for name, mut := range map[string]func(*Spec){
		"range with to_port": func(s *Spec) { s.Forwards[1].ToPort = 80 },
		"unknown link":       func(s *Spec) { s.Forwards[0].Links = []model.LinkID{"isp9"} },
		"bad protocol":       func(s *Spec) { s.Forwards[0].Protos = []model.Protocol{"sctp"} },
		"zero guard":         func(s *Spec) { s.Guard.MaxConns = 0 },
		"no port":            func(s *Spec) { s.Forwards[0].Ports = profile.PortRange{} },
	} {
		spec := forwardSpec()
		mut(&spec)
		if validateForwards(spec) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Фильтр входящих стоит всегда, даже без пробросов: из каналов — только
// ответы и пробросы, остальное отбрасывается; исходящие LAN не трогает.
func TestInboundFilter(t *testing.T) {
	nat := renderNAT(testSpec())
	wans := `iifname { "wan1", "wan2", "wan3" } `
	rules := []string{
		"type filter hook forward priority filter; policy accept;\n",
		wans + "ct state established,related accept\n",
		wans + "ct status dnat accept\n",
		wans + "counter drop\n",
	}
	last := -1
	for _, r := range rules {
		i := strings.Index(nat, r)
		if i < 0 {
			t.Fatalf("NAT table lacks:\n%s---\n%s", r, nat)
		}
		if i < last {
			t.Errorf("rule out of order: %q", r)
		}
		last = i
	}
	if strings.Contains(nat, `iifname "lan"`) || strings.Contains(nat, "oifname { \"wan1\", \"wan2\", \"wan3\" } drop") {
		t.Errorf("filter must not touch traffic from LAN:\n%s", nat)
	}
}

// Устройство проброса ещё без адреса: DNAT нет (входящие отбросит фильтр),
// пометка канала и защита остаются — адрес придёт через SetDevices.
func TestForwardWithoutAddress(t *testing.T) {
	spec := forwardSpec()
	spec.Forwards[0].To = netip.Addr{}
	if err := validateForwards(spec); err != nil {
		t.Fatal(err)
	}
	nat := renderNAT(spec)
	if strings.Contains(nat, "tcp dport 25565 dnat") || !strings.Contains(nat, "dnat ip to 192.168.10.51") {
		t.Errorf("NAT:\n%s", nat)
	}
	if err := validateBinding(DeviceBinding{Forwards: map[string]netip.Addr{"mc": netip.MustParseAddr("::1")}}); err == nil {
		t.Error("IPv6 forward target accepted")
	}
	if err := validateBinding(DeviceBinding{DNS: map[netip.Addr]model.DNSMode{netip.MustParseAddr("192.168.10.5"): "loud"}}); err == nil {
		t.Error("bad dns mode accepted")
	}
}
