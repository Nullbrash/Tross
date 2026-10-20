// Package upnp — решения о пробросах, которые просят программы устройств
// (UPnP IGD, NAT-PMP, PCP): кто может, какой порт, на какой срок. Протоколы
// и ядро — в internal/.
package upnp

import (
	"net/netip"
	"slices"
	"strings"
	"time"

	"tross/core/model"
)

// Via — протокол запроса.
type Via string

const (
	ViaIGD    Via = "igd"
	ViaNATPMP Via = "natpmp"
	ViaPCP    Via = "pcp"
)

// Request — запрос программы открыть порт.
type Request struct {
	Via   Via
	Proto model.Protocol
	// ExtPort — внешний порт; 0 — любой.
	ExtPort uint16
	IntPort uint16
	// Client — внутренний адрес из запроса; Source — откуда запрос пришёл.
	Client, Source netip.Addr
	// Lease — срок; 0 — «навсегда» (UPnP IGD v1).
	Lease time.Duration
	Desc  string
	// AnyPort — при занятом порте можно выдать другой (AddAnyPortMapping,
	// NAT-PMP, PCP); иначе — отказ.
	AnyPort bool
}

// Limits — ограничения для всех устройств.
type Limits struct {
	MinPort      uint16
	MaxLease     time.Duration
	MaxPerDevice int
}

func DefaultLimits() Limits {
	return Limits{MinPort: 1024, MaxLease: time.Hour, MaxPerDevice: 16}
}

// Mapping — действующий проброс.
type Mapping struct {
	Proto   model.Protocol
	ExtPort uint16
	Addr    netip.Addr
	IntPort uint16
}

type Outcome int

const (
	Allow Outcome = iota
	Deny
	// Ask — уровень устройства «спрашивать»: запрос ждёт решения
	// пользователя, программа пока получает отказ.
	Ask
)

// Reason — почему отказ (протоколы переводят в свои коды).
type Reason string

const (
	NotAuthorized Reason = "not_authorized"
	Conflict      Reason = "conflict"
	NoResources   Reason = "no_resources"
)

type Decision struct {
	Outcome Outcome
	ExtPort uint16
	Lease   time.Duration
	// Permanent — просили «навсегда»: срок в ядре — MaxLease, демон
	// продлевает, пока устройство в сети.
	Permanent bool
	Reason    Reason
	Note      string
}

// Taken — порт занят чем-то кроме пробросов программ (ручные пробросы).
type Taken func(proto model.Protocol, port uint16) bool

// Decide — решение по запросу. level — уровень устройства (EffectiveUPnP),
// programs — описания программ, разрешённых «всегда».
func Decide(r Request, level model.UPnPLevel, programs []string, l Limits, existing []Mapping, taken Taken) Decision {
	deny := func(why Reason, note string) Decision { return Decision{Outcome: Deny, Reason: why, Note: note} }
	switch {
	case !r.Source.IsValid() || r.Client != r.Source:
		return deny(NotAuthorized, "internal client must be the requesting device")
	case r.Proto != model.ProtoTCP && r.Proto != model.ProtoUDP:
		return deny(NotAuthorized, "only tcp and udp")
	case r.IntPort < l.MinPort:
		return deny(NotAuthorized, "internal port below the minimum")
	case r.ExtPort != 0 && r.ExtPort < l.MinPort && !r.AnyPort:
		return deny(NotAuthorized, "external port below the minimum")
	}
	switch level {
	case model.UPnPAllow:
	case model.UPnPAsk:
		if r.Desc == "" || !slices.ContainsFunc(programs, func(p string) bool { return strings.EqualFold(p, r.Desc) }) {
			return Decision{Outcome: Ask, Note: "waiting for the user's decision"}
		}
	default:
		return deny(NotAuthorized, "device is not allowed to open ports")
	}
	own, mine := 0, false
	free := func(port uint16) bool {
		if taken != nil && taken(r.Proto, port) {
			return false
		}
		for _, m := range existing {
			if m.Proto == r.Proto && m.ExtPort == port && m.Addr != r.Source {
				return false
			}
		}
		return true
	}
	for _, m := range existing {
		if m.Addr == r.Source {
			own++
			if m.Proto == r.Proto && m.ExtPort == r.ExtPort {
				mine = true
			}
		}
	}
	port := r.ExtPort
	if port < l.MinPort || !free(port) {
		if !r.AnyPort {
			return deny(Conflict, "external port is taken")
		}
		port = pick(r, l, free)
		if port == 0 {
			return deny(NoResources, "no free external port")
		}
		mine = slices.ContainsFunc(existing, func(m Mapping) bool { return m.Proto == r.Proto && m.ExtPort == port && m.Addr == r.Source })
	}
	if !mine && own >= l.MaxPerDevice {
		return deny(NoResources, "too many mappings for this device")
	}
	d := Decision{Outcome: Allow, ExtPort: port, Lease: r.Lease}
	if d.Lease == 0 {
		d.Lease, d.Permanent = l.MaxLease, true
	} else if d.Lease > l.MaxLease {
		d.Lease = l.MaxLease
	}
	return d
}

// pick — свободный порт: внутренний порт, затем вверх от запрошенного по
// кругу в [MinPort, 65535].
func pick(r Request, l Limits, free func(uint16) bool) uint16 {
	if r.IntPort >= l.MinPort && free(r.IntPort) {
		return r.IntPort
	}
	start := max(r.ExtPort, l.MinPort)
	span := 65536 - int(l.MinPort)
	for i := range span {
		p := uint16(int(l.MinPort) + (int(start)-int(l.MinPort)+i)%span)
		if free(p) {
			return p
		}
	}
	return 0
}

// CanDelete — устройство снимает только свои пробросы.
func CanDelete(source netip.Addr, m Mapping) bool { return m.Addr == source }
