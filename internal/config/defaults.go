package config

import (
	"net/netip"
	"path"
	"time"

	"tross/core/lists"
	"tross/core/model"
)

// LinkMarkMask — биты fwmark, отведённые под номер канала. Прокси получают
// свои метки выше (proxy.routing_mark_base), zapret по умолчанию использует
// 0x40000000 — диапазоны не должны пересекаться.
const LinkMarkMask uint32 = 0x0000ff00

func defaultTable(i int) int   { return 100 + i + 1 }
func defaultMark(i int) uint32 { return uint32(i+1) << 8 }
func ptr[T any](v T) *T        { return &v }
func orDefault[T comparable](v *T, d T) {
	var zero T
	if *v == zero {
		*v = d
	}
}

func (c *Config) applyDefaults() {
	orDefault(&c.Daemon.DataDir, "/var/lib/tross")
	orDefault(&c.Log.Level, "info")
	orDefault(&c.Log.Format, "text")
	orDefault(&c.Log.RingSize, 5000)

	orDefault(&c.API.Listen, "127.0.0.1:8080")
	if len(c.API.AllowedNetworks) == 0 {
		c.API.AllowedNetworks = append([]netip.Prefix{
			netip.MustParsePrefix("127.0.0.0/8"),
		}, c.LAN.Networks...)
	}

	for i := range c.Links {
		l := &c.Links[i]
		orDefault(&l.Name, string(l.ID))
		orDefault(&l.Gateway, "auto")
		orDefault(&l.Table, defaultTable(i))
		orDefault(&l.FwMark, defaultMark(i))
		if l.Metered == nil {
			l.Metered = ptr(l.Kind == model.LinkKindLTE)
		}
	}

	m := &c.Monitor
	if len(m.Targets) == 0 {
		m.Targets = []netip.Addr{
			netip.MustParseAddr("1.1.1.1"),
			netip.MustParseAddr("8.8.8.8"),
			netip.MustParseAddr("77.88.8.8"),
		}
	}
	orDefault(&m.Interval, 2*time.Second)
	orDefault(&m.Timeout, time.Second)
	orDefault(&m.Window, 30)
	orDefault(&m.FailAfter, 3)
	orDefault(&m.RecoverAfter, 10)
	orDefault(&m.ThroughputInterval, 6*time.Hour)

	if len(c.Classes) == 0 {
		c.Classes = []Class{{ID: model.ClassDefault}}
	}
	for i := range c.Classes {
		cl := &c.Classes[i]
		orDefault(&cl.Name, string(cl.ID))
		orDefault(&cl.Selector, model.SelectBalanced)
		orDefault(&cl.Stickiness, model.StickNone)
		orDefault(&cl.Method, model.MethodAuto)
		orDefault(&cl.Priority, model.PriorityNormal)
		if cl.Stickiness != model.StickNone {
			orDefault(&cl.StickyTTL, 30*time.Minute)
		}
	}

	d := &c.DNS
	if len(d.Upstreams) == 0 {
		d.Upstreams = []Upstream{
			{Name: "cloudflare", URL: "https://cloudflare-dns.com/dns-query"},
			{Name: "google", URL: "https://dns.google/dns-query"},
			{Name: "quad9", URL: "tls://dns.quad9.net"},
		}
	}
	if len(d.Bootstrap) == 0 {
		d.Bootstrap = []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8")}
	}
	orDefault(&d.CacheSize, 10000)
	orDefault(&d.SetTTL.Min, 5*time.Minute)
	orDefault(&d.SetTTL.Max, 12*time.Hour)
	if d.FirefoxCanaryNXDomain == nil {
		d.FirefoxCanaryNXDomain = ptr(true)
	}
	orDefault(&d.Watchdog.Interval, 5*time.Second)
	orDefault(&d.Watchdog.Failures, 3)

	orDefault(&c.Lists.UpdateInterval, 24*time.Hour)
	for i := range c.Lists.Sources {
		orDefault(&c.Lists.Sources[i].Purpose, lists.PurposeBypass)
	}

	orDefault(&c.DPI.NFQWS, "/opt/zapret/nfq/nfqws")
	orDefault(&c.DPI.QueueBase, 200)
	orDefault(&c.DPI.RecheckInterval, 24*time.Hour)

	p := &c.Proxy
	orDefault(&p.Engine, "mihomo")
	orDefault(&p.Binary, "/usr/local/lib/tross/mihomo")
	// path, а не filepath: пути целевой системы всегда в формате Linux.
	orDefault(&p.WorkDir, path.Join(c.Daemon.DataDir, "mihomo"))
	orDefault(&p.Controller, "127.0.0.1:9090")
	orDefault(&p.TProxyPortBase, 7900)
	orDefault(&p.RoutingMarkBase, 0x00010000)

	if c.Devices.NotifyNew == nil {
		c.Devices.NotifyNew = ptr(true)
	}
	orDefault(&c.Devices.DefaultDNSMode, model.DNSObserve)
}
