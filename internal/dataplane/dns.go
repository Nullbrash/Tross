package dataplane

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"tross/core/model"
)

// nftDNSTable — перехват DNS домашней сети. Переживает остановку демона, как
// NAT: без демона запросы дома уходят запасному резолверу, а не в пустоту
// (у устройств DNS — адрес мини-ПК); снимает только purge.
const nftDNSTable = "tross_dns"

// DNSSpec — перехват DNS. Невалидный Listen — перехвата нет.
type DNSSpec struct {
	// Listen — резолвер демона на адресе LAN.
	Listen netip.AddrPort
	// Fallback — запасной резолвер на мини-ПК: ему уходят запросы дома, пока
	// демона нет; невалиден — запросы к мини-ПК без демона не отвечаются.
	Fallback netip.AddrPort
	// Default — режим устройств, не перечисленных в Devices.
	Default model.DNSMode
	Devices map[netip.Addr]model.DNSMode
}

func (d DNSSpec) enabled() bool { return d.Listen.IsValid() }

func validateDNS(d DNSSpec) error {
	if !d.enabled() {
		return nil
	}
	if !d.Listen.Addr().Is4() || d.Fallback.IsValid() && !d.Fallback.Addr().Is4() {
		return fmt.Errorf("dns: listen %s / fallback %s: want IPv4", d.Listen, d.Fallback)
	}
	if !d.Default.Valid() {
		return fmt.Errorf("dns: bad default mode %q", d.Default)
	}
	for a, m := range d.Devices {
		if !a.Is4() || !m.Valid() {
			return fmt.Errorf("dns: device %s: bad address or mode %q", a, m)
		}
	}
	return nil
}

// renderDNS — таблица перехвата целиком. up — резолвер демона отвечает:
// обычный DNS на чужие серверы — ему (режим redirect). Иначе всё, что дом
// спрашивает у мини-ПК, и перехваченное — запасному резолверу.
//
// Режимы устройства: redirect — обычный DNS (53) на чужие серверы — к нам;
// block — DNS (53) и DoT (853) на чужие серверы отбрасываются; observe и
// exempt — не трогаются (DoT и DoH не перехватываются никогда: Android со
// строгим «Частным DNS» остался бы без интернета).
func renderDNS(spec Spec, up bool) string {
	d := spec.DNS
	var b strings.Builder
	fmt.Fprintf(&b, "add table inet %s\ndelete table inet %s\n", nftDNSTable, nftDNSTable)
	if !d.enabled() {
		return b.String()
	}
	byMode := map[model.DNSMode][]string{}
	var explicit []string
	for a, m := range d.Devices {
		byMode[m] = append(byMode[m], a.String())
		explicit = append(explicit, a.String())
	}
	set := func(name string, elems []string) {
		slices.Sort(elems)
		fmt.Fprintf(&b, "\tset %s {\n\t\ttype ipv4_addr\n", name)
		if len(elems) > 0 {
			fmt.Fprintf(&b, "\t\telements = { %s }\n", strings.Join(elems, ", "))
		}
		b.WriteString("\t}\n")
	}
	lan, own := quote(spec.LANInterface), d.Listen.Addr()
	target := d.Listen
	if !up {
		target = d.Fallback
	}
	// who — устройства режима: перечисленные с ним и, если режим — по
	// умолчанию, все не перечисленные.
	who := func(m model.DNSMode, set string) []string {
		out := []string{"ip saddr @" + set}
		if d.Default == m {
			out = append(out, "ip saddr != @dns_explicit")
		}
		return out
	}
	fmt.Fprintf(&b, "table inet %s {\n", nftDNSTable)
	set("dns_explicit", explicit)
	set("dns_redirect", byMode[model.DNSRedirect])
	set("dns_block", byMode[model.DNSBlock])
	b.WriteString("\tchain prerouting {\n\t\ttype nat hook prerouting priority dstnat - 5; policy accept;\n")
	if !up && target.IsValid() {
		fmt.Fprintf(&b, "\t\tiifname %s ip daddr %s meta l4proto { tcp, udp } th dport %d dnat ip to %s\n", lan, own, d.Listen.Port(), target)
	}
	if target.IsValid() {
		for _, sel := range who(model.DNSRedirect, "dns_redirect") {
			fmt.Fprintf(&b, "\t\tiifname %s %s ip daddr != %s meta l4proto { tcp, udp } th dport 53 dnat ip to %s\n", lan, sel, own, target)
		}
	}
	b.WriteString("\t}\n")
	b.WriteString("\tchain forward {\n\t\ttype filter hook forward priority filter - 5; policy accept;\n")
	for _, sel := range who(model.DNSBlock, "dns_block") {
		fmt.Fprintf(&b, "\t\tiifname %s %s meta l4proto { tcp, udp } th dport { 53, 853 } drop\n", lan, sel)
	}
	b.WriteString("\t}\n}\n")
	return b.String()
}
