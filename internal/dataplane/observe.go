package dataplane

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"tross/core/model"
)

// Connection — соединение из conntrack, размеченное Tross.
type Connection struct {
	Proto string
	// Src и Dst — исходное направление, до NAT.
	Src netip.AddrPort
	Dst netip.AddrPort
	// Соединения без метки (канал не назначен — идут по основной таблице)
	// в список не попадают: Tross их не разметил.
	Link model.LinkID
	// Class пуст у собственного трафика машины (пробы, замеры скорости).
	Class   model.TrafficClass
	State   string
	Timeout time.Duration
	// Packets и Bytes — в обе стороны; нули — учёт conntrack выключен
	// (net.netfilter.nf_conntrack_acct).
	Packets uint64
	Bytes   uint64
}

// Pin — закрепление в множестве ядра: новые соединения устройства этого
// класса (сервиса, адреса) идут в Link, пока не истечёт срок.
type Pin struct {
	Class   model.TrafficClass
	Service string
	Device  netip.Addr
	// Dst — у закреплений «устройство + адрес назначения».
	Dst     netip.Addr
	Link    model.LinkID
	Expires time.Duration
}

// decodeMark — канал и класс по метке соединения (см. LinkMarkMask, classMarkMask).
func decodeMark(spec Spec, mark uint32) (model.LinkID, model.TrafficClass) {
	var link model.LinkID
	if lm := mark & LinkMarkMask; lm != 0 {
		for _, l := range spec.Links {
			if l.FwMark == lm {
				link = l.Link.ID
			}
		}
	}
	var class model.TrafficClass
	c := spec.Classify.withDefault()
	if cid := mark & classMarkMask; cid != 0 && int(cid) <= len(c.Classes) {
		class = c.Classes[cid-1]
	}
	return link, class
}

// pinSet — множество закреплений и что означают его элементы.
type pinSet struct {
	name    string
	class   model.TrafficClass
	service string
	link    model.LinkID
	withDst bool
}

// pinSets — все множества закреплений в том же составе, что ставит renderClassifySets.
func pinSets(spec Spec) []pinSet {
	c := spec.Classify.withDefault()
	var out []pinSet
	for _, cl := range c.Classes {
		p := c.Policies[cl]
		if p.Pin == model.StickNone || p.Pin == "" || p.PinTTL <= 0 {
			continue
		}
		for i, l := range spec.Links {
			out = append(out, pinSet{name: stickySet(c.classID(cl), i), class: cl, link: l.Link.ID, withDst: p.Pin == model.StickDestination})
		}
	}
	for si, svc := range c.Services {
		for i, l := range spec.Links {
			out = append(out, pinSet{name: serviceSet(si, i), class: c.serviceClass(svc), service: svc, link: l.Link.ID})
		}
	}
	return out
}

// parsePinSet разбирает `nft -j list set`: элемент — строка адреса, пара
// {"concat": [...]} или объект {"elem": {"val": …, "expires": секунд}}.
func parsePinSet(ps pinSet, data []byte) ([]Pin, error) {
	var doc struct {
		Nftables []struct {
			Set *struct {
				Elem []json.RawMessage
			}
		}
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("set %s: %w", ps.name, err)
	}
	var out []Pin
	for _, o := range doc.Nftables {
		if o.Set == nil {
			continue
		}
		for _, raw := range o.Set.Elem {
			var wrapped struct {
				Elem *struct {
					Val     json.RawMessage
					Expires int64
				}
			}
			val, expires := raw, int64(0)
			if json.Unmarshal(raw, &wrapped) == nil && wrapped.Elem != nil {
				val, expires = wrapped.Elem.Val, wrapped.Elem.Expires
			}
			var addrs []string
			var one string
			var pair struct {
				Concat []string
			}
			switch {
			case json.Unmarshal(val, &one) == nil:
				addrs = []string{one}
			case json.Unmarshal(val, &pair) == nil:
				addrs = pair.Concat
			default:
				return nil, fmt.Errorf("set %s: unexpected element %s", ps.name, raw)
			}
			if want := map[bool]int{false: 1, true: 2}[ps.withDst]; len(addrs) != want {
				return nil, fmt.Errorf("set %s: element %s has %d parts, want %d", ps.name, raw, len(addrs), want)
			}
			p := Pin{Class: ps.class, Service: ps.service, Link: ps.link, Expires: time.Duration(expires) * time.Second}
			var err error
			if p.Device, err = netip.ParseAddr(addrs[0]); err != nil {
				return nil, fmt.Errorf("set %s: %w", ps.name, err)
			}
			if ps.withDst {
				if p.Dst, err = netip.ParseAddr(addrs[1]); err != nil {
					return nil, fmt.Errorf("set %s: %w", ps.name, err)
				}
			}
			out = append(out, p)
		}
	}
	return out, nil
}

// tcpStates — состояния TCP conntrack (enum tcp_conntrack ядра).
var tcpStates = [...]string{"none", "syn_sent", "syn_recv", "established", "fin_wait", "close_wait", "last_ack", "time_wait", "close", "syn_sent2"}

func tcpState(s uint8) string {
	if int(s) < len(tcpStates) {
		return tcpStates[s]
	}
	return fmt.Sprint(s)
}

func protoName(p uint8) string {
	switch p {
	case 1:
		return "icmp"
	case 6:
		return string(model.ProtoTCP)
	case 17:
		return string(model.ProtoUDP)
	}
	return fmt.Sprint(p)
}
