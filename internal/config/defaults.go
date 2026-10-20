package config

import (
	"net/netip"
	"path"
	"time"

	"tross/core/lists"
	"tross/core/model"
	"tross/core/sqm"
)

// LinkMarkMask — биты fwmark, отведённые под номер канала. Прокси получают
// свои метки выше (proxy.routing_mark_base), zapret по умолчанию использует
// 0x40000000 — диапазоны не должны пересекаться.
const LinkMarkMask uint32 = 0x0000ff00

// DPIMarkMask — бит fwmark пакетов движка обхода (совпадает с
// dataplane.DPIMark и меткой nfqws2 по умолчанию).
const DPIMarkMask uint32 = 0x40000000

// TinMarkMask — биты fwmark с корзиной CAKE класса (совпадает с
// dataplane.TinMarkMask); метки прокси не должны их задевать.
const TinMarkMask uint32 = 0x07000000

func defaultTable(i int) int   { return 100 + i + 1 }
func defaultMark(i int) uint32 { return uint32(i+1) << 8 }
func addrs(s ...string) []netip.Addr {
	out := make([]netip.Addr, len(s))
	for i, a := range s {
		out[i] = netip.MustParseAddr(a)
	}
	return out
}

// path, а не filepath: пути целевой системы всегда в формате Linux.
func defaultWorkDir(dataDir string) string { return path.Join(dataDir, "mihomo") }

func ptr[T any](v T) *T { return &v }
func orDefault[T comparable](v *T, d T) {
	var zero T
	if *v == zero {
		*v = d
	}
}

func (c *Config) applyDefaults() {
	orDefault(&c.Daemon.DataDir, "/var/lib/tross")
	orDefault(&c.Daemon.Control, "/run/tross/trossd.sock")
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
		if l.WhitelistDetection == nil {
			l.WhitelistDetection = ptr(true)
		}
		d := sqm.ParamsFor(l.Kind)
		orDefault(&l.SQM.StartPct, int(d.Start*100+0.5))
		orDefault(&l.SQM.MinPct, int(d.Min*100+0.5))
		orDefault(&l.SQM.MaxPct, int(d.Max*100+0.5))
		if l.SQM.Auto == nil {
			l.SQM.Auto = ptr(true)
		}
	}

	c.applyInboundDefaults()

	m := &c.Monitor
	// Цели — зарубежные в разных AS (Cloudflare, Google, Quad9) и российские в
	// разных AS (Яндекс, MSK-IX, Билайн): по двум группам различаются «белые
	// списки» оператора и обрыв. 8.8.4.4 — у 8.8.8.8 бывает отрезан TCP
	// (подробнее — docs/CONTEXT_monitor.md).
	if len(m.Targets) == 0 {
		m.Targets = addrs("1.1.1.1", "8.8.4.4", "9.9.9.9", "77.88.8.8", "195.208.4.1", "194.67.2.114")
	}
	if len(m.WhitelistTargets) == 0 {
		m.WhitelistTargets = addrs("77.88.8.8", "195.208.4.1", "194.67.2.114")
	}
	if len(m.TCPTargets) == 0 {
		m.TCPTargets = []netip.AddrPort{
			netip.MustParseAddrPort("1.1.1.1:443"),
			netip.MustParseAddrPort("8.8.4.4:443"),
			netip.MustParseAddrPort("9.9.9.9:443"),
		}
	}
	orDefault(&m.Interval, 2*time.Second)
	orDefault(&m.Timeout, time.Second)
	orDefault(&m.Window, 30)
	orDefault(&m.FailAfter, 3)
	orDefault(&m.RecoverAfter, 10)
	if len(m.SpeedTest.URLs) == 0 {
		m.SpeedTest.URLs = []string{
			"https://speed.cloudflare.com/__down?bytes=50000000",
			"https://web1.cachefly.net/speedtest/downloading",
		}
	}
	h := &m.HTTPCheck
	if h.Enabled == nil {
		h.Enabled = ptr(true)
	}
	orDefault(&h.Interval, 30*time.Second)
	orDefault(&h.Timeout, 5*time.Second)
	orDefault(&h.FailAfter, 2)
	if len(h.DNS) == 0 {
		// DoH: открытый DNS на порт 53 к сторонним серверам у части
		// провайдеров закрыт — проверка не получила бы адресов и пометила бы
		// исправный канал restricted.
		h.DNS = dnsServers("https://1.1.1.1/dns-query", "https://8.8.4.4/dns-query", "https://9.9.9.9/dns-query")
	}
	if len(h.URLs) == 0 {
		h.URLs = []HTTPCheckURL{
			{URL: "http://cp.cloudflare.com/generate_204", Status: 204},
			{URL: "https://www.gstatic.com/generate_204", Status: 204},
			{URL: "http://detectportal.firefox.com/success.txt", Status: 200, Body: "success"},
			{URL: "http://www.msftconnecttest.com/connecttest.txt", Status: 200, Body: "Microsoft Connect Test"},
			{URL: "https://ya.ru/", Domestic: true},
			{URL: "https://www.gosuslugi.ru/", Domestic: true},
		}
	}
	orDefault(&m.SpeedTest.At, "04:00")
	orDefault(&m.SpeedTest.Duration, 10*time.Second)
	orDefault(&m.SpeedTest.MaxBytes, 200_000_000)

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
		d.Upstreams = DefaultUpstreams()
	}
	orDefault(&d.Race, 2)
	if !d.Fallback.IsValid() && len(d.Listen) > 0 {
		// Запасной резолвер — на том же адресе, порт 5335.
		if ap, err := netip.ParseAddrPort(d.Listen[0]); err == nil {
			d.Fallback = netip.AddrPortFrom(ap.Addr(), 5335)
		}
	}
	if d.Sensitive.Services == nil && d.Sensitive.Domains == nil {
		def := DefaultSensitive()
		d.Sensitive.Services, d.Sensitive.Domains = def.Services, def.Domains
	}
	if len(d.Bootstrap) == 0 {
		d.Bootstrap = addrs("1.1.1.1", "8.8.4.4")
	}
	orDefault(&d.CacheSize, 10000)
	orDefault(&d.SetTTL.Min, 5*time.Minute)
	orDefault(&d.SetTTL.Max, 12*time.Hour)
	c.applyDHCPDefaults()
	if d.FirefoxCanaryNXDomain == nil {
		d.FirefoxCanaryNXDomain = ptr(true)
	}
	orDefault(&d.Watchdog.Interval, 5*time.Second)
	orDefault(&d.Watchdog.Failures, 3)

	orDefault(&c.Lists.UpdateInterval, 24*time.Hour)
	for i := range c.Lists.Sources {
		orDefault(&c.Lists.Sources[i].Purpose, lists.PurposeBypass)
	}

	orDefault(&c.DPI.NFQWS, "/opt/zapret2/nfqws2")
	orDefault(&c.DPI.LuaDir, "/opt/zapret2/lua")
	orDefault(&c.DPI.Dir, "/run/tross-dpi")
	orDefault(&c.DPI.Version, "v1.0.5.2")
	orDefault(&c.DPI.QueueBase, 200)
	orDefault(&c.DPI.RecheckInterval, 24*time.Hour)

	p := &c.Proxy
	orDefault(&p.Engine, "mihomo")
	orDefault(&p.Binary, "/usr/local/lib/tross/mihomo")
	orDefault(&p.WorkDir, defaultWorkDir(c.Daemon.DataDir))
	orDefault(&p.Controller, "127.0.0.1:9090")
	orDefault(&p.TProxyPortBase, 7900)
	orDefault(&p.RoutingMarkBase, 0x00010000)

	if c.Devices.NotifyNew == nil {
		c.Devices.NotifyNew = ptr(true)
	}
	// Обычный DNS (53) на чужие серверы — к резолверу; DoT и DoH не
	// перехватываются в любом режиме, кроме block.
	orDefault(&c.Devices.DefaultDNSMode, model.DNSRedirect)
}
