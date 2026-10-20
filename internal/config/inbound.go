package config

import (
	"fmt"
	"net/netip"
	"slices"

	"tross/core/devices"
	"tross/core/model"
	"tross/core/profile"
)

// Inbound — входящие из интернета к устройствам LAN (D-43): ручные
// пробросы и их общая защита.
type Inbound struct {
	Forwards []PortForward `yaml:"forwards"`
	Guard    InboundGuard  `yaml:"guard"`
}

type PortForward struct {
	Name string `yaml:"name"`
	// Proto — tcp, udp или both.
	Proto string `yaml:"proto"`
	// Port — внешний порт или диапазон «27015-27030».
	Port profile.PortRange `yaml:"port"`
	// To — устройство: IPv4, MAC или id записи реестра (проброс следует за
	// устройством при смене адреса).
	To devices.Ref `yaml:"to"`
	// ToPort — порт на устройстве; 0 — как снаружи (у диапазона — только так).
	ToPort uint16 `yaml:"to_port"`
	// Links — каналы, на которых открыт проброс; пусто — все.
	Links []model.LinkID `yaml:"links"`
}

// Protos — протоколы проброса.
func (f PortForward) Protos() []model.Protocol {
	if f.Proto == "both" {
		return []model.Protocol{model.ProtoTCP, model.ProtoUDP}
	}
	return []model.Protocol{model.Protocol(f.Proto)}
}

// InboundGuard — ограничения на один адрес источника, общие для всех
// пробросов; включены всегда.
type InboundGuard struct {
	NewPerMinute   int `yaml:"new_per_minute"`
	Burst          int `yaml:"burst"`
	MaxConnections int `yaml:"max_connections"`
}

func (c *Config) applyInboundDefaults() {
	for i := range c.Inbound.Forwards {
		orDefault(&c.Inbound.Forwards[i].Proto, "tcp")
	}
	g := &c.Inbound.Guard
	orDefault(&g.NewPerMinute, 20)
	orDefault(&g.Burst, 20)
	orDefault(&g.MaxConnections, 32)
}

func (c *Config) validateInbound(p *problems) {
	names := map[string]bool{}
	for i, f := range c.Inbound.Forwards {
		fp := fmt.Sprintf("inbound.forwards[%d]", i)
		if f.Name == "" || names[f.Name] {
			p.add(fp+".name", "empty or duplicate name %q", f.Name)
		}
		names[f.Name] = true
		if f.Proto != "tcp" && f.Proto != "udp" && f.Proto != "both" {
			p.add(fp+".proto", "%q: want tcp, udp or both", f.Proto)
		}
		if f.Port.From == 0 {
			p.add(fp+".port", "required, 1-65535")
		}
		if f.ToPort != 0 && f.Port.To != f.Port.From {
			p.add(fp+".to_port", "not allowed with a port range: ports are kept as is")
		}
		switch {
		case f.To.IsZero():
			p.add(fp+".to", "required: an IPv4 address in lan.networks, a MAC or a device id")
		case f.To.Addr.IsValid() && !slices.ContainsFunc(c.LAN.Networks, func(n netip.Prefix) bool { return n.Contains(f.To.Addr) }):
			p.add(fp+".to", "%s: not in lan.networks", f.To)
		}
		for _, id := range f.Links {
			if !c.linkExists(id) {
				p.add(fp+".links", "unknown link %q", id)
			}
		}
		// Один порт канала — одному устройству: иначе сработал бы первый
		// проброс, а второй молча не работал.
		for j, o := range c.Inbound.Forwards[:i] {
			if overlaps(f, o, c.Links) {
				p.add(fp, "overlaps forwards[%d] (%s): same protocol, port and link", j, o.Name)
			}
		}
	}
	g := c.Inbound.Guard
	if g.NewPerMinute <= 0 || g.Burst <= 0 || g.MaxConnections <= 0 {
		p.add("inbound.guard", "limits must be positive")
	}
}

func overlaps(a, b PortForward, links []Link) bool {
	if a.Port.From > b.Port.To || b.Port.From > a.Port.To {
		return false
	}
	if !slices.ContainsFunc(a.Protos(), func(p model.Protocol) bool { return slices.Contains(b.Protos(), p) }) {
		return false
	}
	on := func(f PortForward, id model.LinkID) bool { return len(f.Links) == 0 || slices.Contains(f.Links, id) }
	return slices.ContainsFunc(links, func(l Link) bool { return on(a, l.ID) && on(b, l.ID) })
}
