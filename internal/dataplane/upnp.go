package dataplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"tross/core/model"
)

// nftUPnPTable — пробросы, открытые программами устройств (UPnP IGD,
// NAT-PMP, PCP). Отдельная таблица: Setup не заменяет её целиком, как NAT, —
// пробросы переживают перезапуск и остановку демона, а срок каждого держит
// ядро (таймаут элемента): забытый проброс исчезает и без демона.
const nftUPnPTable = "tross_upnp"

// UPnPSpec — пробросы по запросу программ.
type UPnPSpec struct {
	Enabled bool
	// Links — номера каналов в Spec.Links, на которых открываются пробросы.
	Links []int
	// ServicePorts — порты служб UPnP на мини-ПК (UDP 1900, 5351, TCP порт
	// описания IGD): со стороны каналов закрыты всегда.
	UDPPorts []uint16
	TCPPorts []uint16
}

// UPnPMapping — проброс в ядре.
type UPnPMapping struct {
	Proto   model.Protocol `json:"proto"`
	ExtPort uint16         `json:"ext_port"`
	Addr    netip.Addr     `json:"addr"`
	IntPort uint16         `json:"int_port"`
	// Lease — срок при записи; Expires — сколько осталось (из ядра).
	Lease   time.Duration `json:"-"`
	Expires time.Duration `json:"-"`
	Desc    string        `json:"desc,omitempty"`
}

func validateUPnP(spec Spec) error {
	if !spec.UPnP.Enabled {
		return nil
	}
	if len(spec.UPnP.Links) == 0 {
		return errors.New("upnp: no links")
	}
	for _, i := range spec.UPnP.Links {
		if i < 0 || i >= len(spec.Links) {
			return fmt.Errorf("upnp: link index %d", i)
		}
	}
	return nil
}

func portList(ps []uint16) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = fmt.Sprint(p)
	}
	return strings.Join(s, ", ")
}

// renderUPnP — таблица пробросов программ: объекты создаются, если их нет
// (add — пробросы в отображении сохраняются), цепочки собираются заново.
// Выключено — таблица снимается.
func renderUPnP(spec Spec) string {
	t := "inet " + nftUPnPTable
	var b strings.Builder
	if !spec.UPnP.Enabled {
		fmt.Fprintf(&b, "add table %s\ndelete table %s\n", t, t)
		return b.String()
	}
	u := spec.UPnP
	var links []LinkSpec
	for _, i := range u.Links {
		links = append(links, spec.Links[i])
	}
	wans := ifnames(links)
	g := spec.Guard
	if g.NewPerMinute <= 0 {
		g = InboundGuard{NewPerMinute: 20, Burst: 20, MaxConns: 32}
	}
	fmt.Fprintf(&b, "add table %s\n", t)
	fmt.Fprintf(&b, "add map %s portmap { type inet_proto . inet_service : ipv4_addr . inet_service; flags timeout; }\n", t)
	fmt.Fprintf(&b, "add set %s ports { type inet_proto . inet_service; flags timeout; }\n", t)
	fmt.Fprintf(&b, "add set %s rate { type ipv4_addr; size %d; flags dynamic,timeout; timeout 2m; }\n", t, guardSetSize)
	fmt.Fprintf(&b, "add set %s conn { type ipv4_addr; size %d; flags dynamic; }\n", t, guardSetSize)
	chains := []struct{ name, hook string }{
		// Защита — до DNAT, как у ручных пробросов.
		{"guard", "type filter hook prerouting priority dstnat - 10; policy accept;"},
		{"inbound", ""},
		{"natpre", "type nat hook prerouting priority dstnat; policy accept;"},
		// Метка канала — раньше таблицы tross (mangle): ответ устройства
		// уходит в канал запроса.
		{"markpre", "type filter hook prerouting priority mangle - 1; policy accept;"},
		// Службы UPnP мини-ПК — только для LAN.
		{"svcin", "type filter hook input priority filter; policy accept;"},
	}
	for _, c := range chains {
		if c.hook != "" {
			fmt.Fprintf(&b, "add chain %s %s { %s }\n", t, c.name, c.hook)
		} else {
			fmt.Fprintf(&b, "add chain %s %s\n", t, c.name)
		}
		fmt.Fprintf(&b, "flush chain %s %s\n", t, c.name)
	}
	fmt.Fprintf(&b, "add rule %s guard iifname { %s } ct state new meta l4proto . th dport @ports jump inbound\n", t, wans)
	fmt.Fprintf(&b, "add rule %s inbound add @rate { ip saddr limit rate over %d/minute burst %d packets } counter drop\n", t, g.NewPerMinute, g.Burst)
	fmt.Fprintf(&b, "add rule %s inbound add @conn { ip saddr ct count over %d } counter drop\n", t, g.MaxConns)
	fmt.Fprintf(&b, "add rule %s natpre iifname { %s } dnat ip to meta l4proto . th dport map @portmap\n", t, wans)
	for _, l := range links {
		fmt.Fprintf(&b, "add rule %s markpre iifname %s ct state new meta l4proto . th dport @ports meta mark set %#x ct mark set %#x\n", t, quote(l.Link.Interface), l.FwMark, l.FwMark)
	}
	all := ifnames(spec.Links)
	if len(u.UDPPorts) > 0 {
		fmt.Fprintf(&b, "add rule %s svcin iifname { %s } udp dport { %s } counter drop\n", t, all, portList(u.UDPPorts))
	}
	if len(u.TCPPorts) > 0 {
		fmt.Fprintf(&b, "add rule %s svcin iifname { %s } tcp dport { %s } counter drop\n", t, all, portList(u.TCPPorts))
	}
	return b.String()
}

// Описание программы — в комментарии элемента: только безопасные символы.
func nftComment(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '"' || r == '\\' || r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if r := []rune(s); len(r) > 64 {
		s = string(r[:64])
	}
	return s
}

func validMapping(m UPnPMapping) error {
	if m.Proto != model.ProtoTCP && m.Proto != model.ProtoUDP || m.ExtPort == 0 || m.IntPort == 0 || !m.Addr.Is4() || m.Lease < time.Second {
		return fmt.Errorf("upnp: bad mapping %+v", m)
	}
	return nil
}

// renderUPnPSet — замена проброса (продление — тот же проброс с новым сроком).
func renderUPnPSet(m UPnPMapping) string {
	t := "inet " + nftUPnPTable
	key := fmt.Sprintf("%s . %d", m.Proto, m.ExtPort)
	sec := int(m.Lease / time.Second)
	var b strings.Builder
	fmt.Fprintf(&b, "destroy element %s portmap { %s }\n", t, key)
	fmt.Fprintf(&b, "destroy element %s ports { %s }\n", t, key)
	fmt.Fprintf(&b, "add element %s portmap { %s timeout %ds comment \"%s\" : %s . %d }\n", t, key, sec, nftComment(m.Desc), m.Addr, m.IntPort)
	fmt.Fprintf(&b, "add element %s ports { %s timeout %ds }\n", t, key, sec)
	return b.String()
}

func renderUPnPDelete(proto model.Protocol, port uint16) string {
	t := "inet " + nftUPnPTable
	key := fmt.Sprintf("%s . %d", proto, port)
	return fmt.Sprintf("destroy element %s portmap { %s }\ndestroy element %s ports { %s }\n", t, key, t, key)
}

// parseUPnPMap — элементы отображения из `nft -j list map`.
func parseUPnPMap(b []byte) ([]UPnPMapping, error) {
	var doc struct {
		Nftables []struct {
			Map *struct {
				Elem [][2]json.RawMessage `json:"elem"`
			} `json:"map"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	type concat struct {
		Concat []json.RawMessage `json:"concat"`
	}
	var out []UPnPMapping
	for _, n := range doc.Nftables {
		if n.Map == nil {
			continue
		}
		for _, e := range n.Map.Elem {
			var key struct {
				Elem struct {
					Val     concat `json:"val"`
					Timeout int    `json:"timeout"`
					Expires int    `json:"expires"`
					Comment string `json:"comment"`
				} `json:"elem"`
			}
			var val concat
			if json.Unmarshal(e[0], &key) != nil || json.Unmarshal(e[1], &val) != nil || len(key.Elem.Val.Concat) != 2 || len(val.Concat) != 2 {
				continue
			}
			var proto, addr string
			var ext, in uint16
			if json.Unmarshal(key.Elem.Val.Concat[0], &proto) != nil || json.Unmarshal(key.Elem.Val.Concat[1], &ext) != nil ||
				json.Unmarshal(val.Concat[0], &addr) != nil || json.Unmarshal(val.Concat[1], &in) != nil {
				continue
			}
			a, err := netip.ParseAddr(addr)
			if err != nil {
				continue
			}
			out = append(out, UPnPMapping{Proto: model.Protocol(proto), ExtPort: ext, Addr: a, IntPort: in,
				Lease: time.Duration(key.Elem.Timeout) * time.Second, Expires: time.Duration(key.Elem.Expires) * time.Second, Desc: key.Elem.Comment})
		}
	}
	slices.SortFunc(out, func(a, b UPnPMapping) int {
		if a.Proto != b.Proto {
			return strings.Compare(string(a.Proto), string(b.Proto))
		}
		return int(a.ExtPort) - int(b.ExtPort)
	})
	return out, nil
}
