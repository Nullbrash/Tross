package config

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// DHCP — раздача адресов в LAN: dnsmasq отдельной службой (живёт и без
// демона), демон пишет ему конфиг и закреплённые адреса устройств.
type DHCP struct {
	Enabled bool `yaml:"enabled"`
	// Range — «первый-последний» адрес раздачи; пусто — .100–.249 сети
	// /24 из lan.networks.
	Range string `yaml:"range"`
	// Lease — срок аренды; устройство продлевает её на половине срока.
	Lease time.Duration `yaml:"lease"`
	// Gateway — шлюз и DNS для устройств (адрес мини-ПК в LAN); пусто —
	// адрес из dns.listen.
	Gateway netip.Addr `yaml:"gateway"`
	// Dir — каталог конфига, закреплённых адресов и аренд dnsmasq. Не внутри
	// data_dir: dnsmasq перечитывает закреплённые адреса, уже сбросив права
	// root, — каталог и файлы должны быть доступны на чтение всем.
	Dir string `yaml:"dir"`
	// PIDFile — файл процесса dnsmasq (сигнал перечитать закреплённые адреса).
	PIDFile string `yaml:"pid_file"`
	// Unit — служба systemd с dnsmasq (перезапуск при смене основного
	// конфига); none — службы нет, dnsmasq запускают вручную.
	Unit string `yaml:"unit"`
}

// DHCPRange — разобранный lan.dhcp.range.
func (d DHCP) DHCPRange() (first, last netip.Addr, err error) {
	a, b, ok := strings.Cut(d.Range, "-")
	if !ok {
		return first, last, fmt.Errorf("%q: want first-last", d.Range)
	}
	if first, err = netip.ParseAddr(strings.TrimSpace(a)); err != nil {
		return
	}
	last, err = netip.ParseAddr(strings.TrimSpace(b))
	return
}

func (c *Config) applyDHCPDefaults() {
	d := &c.LAN.DHCP
	orDefault(&d.Lease, 12*time.Hour)
	orDefault(&d.Dir, "/var/lib/tross-dhcp")
	orDefault(&d.PIDFile, "/run/tross-dhcp/dnsmasq.pid")
	orDefault(&d.Unit, "tross-dhcp.service")
	if !d.Gateway.IsValid() && len(c.DNS.Listen) > 0 {
		if ap, err := netip.ParseAddrPort(c.DNS.Listen[0]); err == nil {
			d.Gateway = ap.Addr()
		}
	}
	if d.Range == "" && len(c.LAN.Networks) > 0 && c.LAN.Networks[0].Bits() == 24 && c.LAN.Networks[0].Addr().Is4() {
		b := c.LAN.Networks[0].Masked().Addr().As4()
		b[3] = 100
		first := netip.AddrFrom4(b)
		b[3] = 249
		d.Range = first.String() + "-" + netip.AddrFrom4(b).String()
	}
}

func (c *Config) validateDHCP(p *problems) {
	d := c.LAN.DHCP
	if !d.Enabled {
		return
	}
	first, last, err := d.DHCPRange()
	if err != nil {
		p.add("lan.dhcp.range", "%v", err)
		return
	}
	var net netip.Prefix
	for _, n := range c.LAN.Networks {
		if n.Contains(first) && n.Contains(last) {
			net = n
		}
	}
	switch {
	case !first.Is4() || !last.Is4() || last.Less(first):
		p.add("lan.dhcp.range", "%q: want IPv4 first-last, first <= last", d.Range)
	case !net.IsValid():
		p.add("lan.dhcp.range", "%q: not inside one of lan.networks", d.Range)
	case first == net.Masked().Addr():
		p.add("lan.dhcp.range", "%q: starts at the network address", d.Range)
	}
	if !d.Gateway.IsValid() {
		p.add("lan.dhcp.gateway", "required when dns.listen is not set")
	} else {
		if !slices.ContainsFunc(c.LAN.Networks, func(n netip.Prefix) bool { return n.Contains(d.Gateway) }) {
			p.add("lan.dhcp.gateway", "%s: not in lan.networks", d.Gateway)
		}
		if !d.Gateway.Less(first) && !last.Less(d.Gateway) {
			p.add("lan.dhcp.gateway", "%s: inside the range %s", d.Gateway, d.Range)
		}
	}
	if d.Lease < 2*time.Minute {
		p.add("lan.dhcp.lease", "%v: at least 2m", d.Lease)
	}
	if d.PIDFile == "" {
		p.add("lan.dhcp.pid_file", "required")
	}
	if strings.ContainsAny(d.Dir+d.PIDFile, "\n\r") || !strings.HasPrefix(d.Dir, "/") {
		p.add("lan.dhcp.dir", "%q: want an absolute path", d.Dir)
	}
}
