package dataplane

import (
	"net/netip"
	"strings"
	"testing"

	"tross/core/decision"
	"tross/core/model"
)

func dnsSpec() Spec {
	return Spec{LANInterface: "lan", DNS: DNSSpec{
		Listen:   netip.MustParseAddrPort("192.168.77.1:53"),
		Fallback: netip.MustParseAddrPort("192.168.77.1:5335"),
		Default:  model.DNSRedirect,
		Devices: map[netip.Addr]model.DNSMode{
			netip.MustParseAddr("192.168.77.20"): model.DNSExempt,
			netip.MustParseAddr("192.168.77.21"): model.DNSBlock,
		},
	}}
}

func TestRenderDNS(t *testing.T) {
	spec := dnsSpec()
	up := renderDNS(spec, true)
	for _, want := range []string{
		"elements = { 192.168.77.20, 192.168.77.21 }",
		// Устройства без своего режима — обычный DNS на чужие серверы — к нам.
		`iifname "lan" ip saddr != @dns_explicit ip daddr != 192.168.77.1 meta l4proto { tcp, udp } th dport 53 dnat ip to 192.168.77.1:53`,
		`iifname "lan" ip saddr @dns_block meta l4proto { tcp, udp } th dport { 53, 853 } drop`,
	} {
		if !strings.Contains(up, want) {
			t.Errorf("up lacks:\n%s\n---\n%s", want, up)
		}
	}
	// Демон работает — свой адрес не перенаправляется (там слушает он сам).
	if strings.Contains(up, "ip daddr 192.168.77.1 ") {
		t.Errorf("up redirects own address:\n%s", up)
	}
	down := renderDNS(spec, false)
	for _, want := range []string{
		// Демона нет: всё, что дом спрашивает у мини-ПК, — запасному.
		`iifname "lan" ip daddr 192.168.77.1 meta l4proto { tcp, udp } th dport 53 dnat ip to 192.168.77.1:5335`,
		`ip daddr != 192.168.77.1 meta l4proto { tcp, udp } th dport 53 dnat ip to 192.168.77.1:5335`,
	} {
		if !strings.Contains(down, want) {
			t.Errorf("down lacks:\n%s\n---\n%s", want, down)
		}
	}
	// По умолчанию наблюдение — перенаправляются только перечисленные.
	spec.DNS.Default = model.DNSObserve
	spec.DNS.Devices[netip.MustParseAddr("192.168.77.22")] = model.DNSRedirect
	obs := renderDNS(spec, true)
	if strings.Contains(obs, "!= @dns_explicit") || !strings.Contains(obs, "ip saddr @dns_redirect ip daddr != 192.168.77.1") {
		t.Errorf("observe default:\n%s", obs)
	}
	// Без резолвера — таблица только снимается.
	if got := renderDNS(Spec{LANInterface: "lan"}, true); strings.Contains(got, "chain") {
		t.Errorf("disabled dns renders rules:\n%s", got)
	}
}

func TestValidateDNS(t *testing.T) {
	if err := validateDNS(dnsSpec().DNS); err != nil {
		t.Errorf("valid: %v", err)
	}
	bad := dnsSpec().DNS
	bad.Default = "maybe"
	if validateDNS(bad) == nil {
		t.Error("bad default mode accepted")
	}
	if validateDNS(DNSSpec{}) != nil {
		t.Error("disabled dns must be valid")
	}
}

// Канал, выбранный резолвером, — после закреплений и раньше долей, только
// среди долей плана, с запоминанием закрепления.
func TestRenderPlanDomainLink(t *testing.T) {
	spec, c := classifySpec(t)
	plan := []decision.ClassPlan{
		{Class: model.ClassGaming, Shares: []decision.LinkShare{{Link: "isp1", Weight: 1}, {Link: "isp2", Weight: 1}}, PinLinks: []model.LinkID{"isp1", "isp2"}},
		{Class: model.ClassStreaming, Shares: []decision.LinkShare{{Link: "isp1", Weight: 1}}},
	}
	got := renderPlan(c, spec.Links, plan)
	pin := "add rule inet tross cls1 ip saddr @tross_s1_0 update"
	dl := "add rule inet tross cls1 ip daddr @tross_dl1 meta mark set 0x201 update @tross_s1_1 { ip saddr } goto commit\n"
	pick := "add rule inet tross cls1 meta mark set jhash"
	if !strings.Contains(got, dl) {
		t.Fatalf("plan lacks domain-link rule:\n%s---\n%s", dl, got)
	}
	if !(strings.Index(got, pin) < strings.Index(got, dl) && strings.Index(got, dl) < strings.Index(got, pick)) {
		t.Error("order must be pins → domain link → shares")
	}
	if strings.Contains(got, "tross_dl2") {
		t.Error("LTE is not in the gaming plan — its domain-link set must be ignored")
	}
	if strings.Contains(got, "cls3 ip daddr @tross_dl") {
		t.Error("one share — nothing to choose")
	}
	sets := renderClassifySets(c, spec.Links)
	if !strings.Contains(sets, "set tross_dl0 {") || !strings.Contains(sets, "set tross_dl2 {") {
		t.Errorf("domain-link sets missing:\n%s", sets)
	}
}
