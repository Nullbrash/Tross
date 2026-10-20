package config

import (
	"cmp"
	"slices"
	"time"

	"tross/core/model"
)

// UPnP — пробросы по запросу программ доверенных устройств (UPnP IGD,
// NAT-PMP, PCP). Службы — только на адресе LAN (lan.dhcp.gateway).
type UPnP struct {
	Enabled bool `yaml:"enabled"`
	// HTTPPort — порт описания и управления IGD на адресе LAN.
	HTTPPort uint16 `yaml:"http_port"`
	// MaxLease — предел срока проброса; просьбы «навсегда» продлеваются,
	// пока устройство в сети.
	MaxLease     time.Duration `yaml:"max_lease"`
	MaxPerDevice int           `yaml:"max_per_device"`
	// Links — каналы, на которых открываются пробросы; пусто — все проводные
	// (у LTE обычно общий адрес оператора, а трафик дорогой).
	Links []model.LinkID `yaml:"links"`
}

func (c *Config) applyUPnPDefaults() {
	u := &c.UPnP
	orDefault(&u.HTTPPort, 5000)
	orDefault(&u.MaxLease, time.Hour)
	orDefault(&u.MaxPerDevice, 16)
}

// UPnPLinks — каналы пробросов программ по приоритету (первый — основной:
// его адрес сообщается программам как внешний).
func (c *Config) UPnPLinks() []Link {
	var out []Link
	for _, l := range c.Links {
		if len(c.UPnP.Links) == 0 && l.Kind == model.LinkKindWired || slices.Contains(c.UPnP.Links, l.ID) {
			out = append(out, l)
		}
	}
	slices.SortStableFunc(out, func(a, b Link) int { return cmp.Compare(a.Priority, b.Priority) })
	return out
}

func (c *Config) validateUPnP(p *problems) {
	u := c.UPnP
	if !u.Enabled {
		return
	}
	for _, id := range u.Links {
		if !c.linkExists(id) {
			p.add("upnp.links", "unknown link %q", id)
		}
	}
	if len(c.UPnPLinks()) == 0 {
		p.add("upnp.links", "no links: list them or add a wired link")
	}
	if !c.LAN.DHCP.Gateway.IsValid() {
		p.add("upnp", "needs the LAN address of the machine: dns.listen or lan.dhcp.gateway")
	}
	if u.MaxLease < 2*time.Minute {
		p.add("upnp.max_lease", "%v: at least 2m", u.MaxLease)
	}
	if u.MaxPerDevice <= 0 {
		p.add("upnp.max_per_device", "must be positive")
	}
	if u.HTTPPort == 5351 || u.HTTPPort == 1900 {
		p.add("upnp.http_port", "%d is taken by NAT-PMP/SSDP", u.HTTPPort)
	}
}
