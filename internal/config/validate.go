package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"

	coredns "tross/core/dns"
	coredpi "tross/core/dpi"
	"tross/core/lists"
	"tross/core/model"
	"tross/core/profile"
)

// Идентификаторы каналов и классов входят в имена объектов nftables и метрик —
// поэтому только строчные латинские буквы, цифры, '_' и '-'.
var (
	linkIDRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,14}$`)
	classIDRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	sourceIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
)

// zapretMark — метка, которую nfqws ставит на свои пакеты по умолчанию.
const zapretMark uint32 = 0x40000000

type problems []error

func (p *problems) add(field, format string, args ...any) {
	*p = append(*p, fmt.Errorf("%s: %s", field, fmt.Sprintf(format, args...)))
}

// Validate проверяет конфигурацию после применения значений по умолчанию
// и возвращает все найденные ошибки разом.
func (c *Config) Validate() error {
	var p problems
	c.validateLog(&p)
	c.validateAPI(&p)
	c.validateLAN(&p)
	c.validateLinks(&p)
	c.validateMonitor(&p)
	c.validateClasses(&p)
	c.validateClassify(&p)
	c.validateInbound(&p)
	c.validateDNS(&p)
	c.validateLists(&p)
	c.validateDPI(&p)
	c.validateProxy(&p)
	if !c.Devices.DefaultDNSMode.Valid() {
		p.add("devices.default_dns_mode", "invalid mode %q", c.Devices.DefaultDNSMode)
	}
	return errors.Join(p...)
}

func (c *Config) validateLog(p *problems) {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(c.Log.Level)); err != nil {
		p.add("log.level", "%v", err)
	}
	if c.Log.Format != "text" && c.Log.Format != "json" {
		p.add("log.format", "want text or json, got %q", c.Log.Format)
	}
	if c.Log.RingSize < 1 {
		p.add("log.ring_size", "must be positive")
	}
}

// ipv4HostPort — «IPv4:порт». Пустой хост не годится: слушание на всех
// адресах включило бы и IPv6, который не поддерживается.
func ipv4HostPort(s string) error {
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		return err
	}
	if a, err := netip.ParseAddr(host); err != nil || !a.Is4() {
		return fmt.Errorf("want IPv4:port, got %q", s)
	}
	return nil
}

func (c *Config) validateAPI(p *problems) {
	if err := ipv4HostPort(c.API.Listen); err != nil {
		p.add("api.listen", "%v", err)
	}
	for _, n := range c.API.AllowedNetworks {
		if !n.IsValid() || !n.Addr().Is4() {
			p.add("api.allowed_networks", "%s: only IPv4 is supported", n)
		}
	}
}

func (c *Config) validateLAN(p *problems) {
	if c.LAN.Interface == "" {
		p.add("lan.interface", "required")
	}
	if len(c.LAN.Networks) == 0 {
		p.add("lan.networks", "at least one network is required")
	}
	for _, n := range c.LAN.Networks {
		if !n.Addr().Is4() {
			p.add("lan.networks", "%s: only IPv4 is supported", n)
		}
	}
}

func (c *Config) validateLinks(p *problems) {
	if len(c.Links) == 0 {
		*p = append(*p, errNoLinks)
		return
	}
	ids := map[model.LinkID]bool{}
	ifaces := map[string]bool{}
	tables := map[int]bool{}
	marks := map[uint32]bool{}
	for i, l := range c.Links {
		f := fmt.Sprintf("links[%d]", i)
		if !linkIDRe.MatchString(string(l.ID)) {
			p.add(f+".id", "%q: want [a-z0-9][a-z0-9_-]{0,14}", l.ID)
		}
		if ids[l.ID] {
			p.add(f+".id", "duplicate %q", l.ID)
		}
		ids[l.ID] = true
		if !l.Kind.Valid() {
			p.add(f+".kind", "want wired or lte, got %q", l.Kind)
		}
		switch {
		case l.Interface == "":
			p.add(f+".interface", "required")
		case l.Interface == c.LAN.Interface:
			p.add(f+".interface", "%q is the LAN interface", l.Interface)
		case ifaces[l.Interface]:
			p.add(f+".interface", "duplicate %q", l.Interface)
		}
		ifaces[l.Interface] = true
		if l.Gateway != "auto" {
			if a, err := netip.ParseAddr(l.Gateway); err != nil || !a.Is4() {
				p.add(f+".gateway", "want \"auto\" or IPv4 address, got %q", l.Gateway)
			}
		}
		// 253–255 — системные таблицы default/main/local.
		if l.Table <= 0 || l.Table >= 253 && l.Table <= 255 {
			p.add(f+".table", "%d is reserved or invalid", l.Table)
		}
		if tables[l.Table] {
			p.add(f+".table", "duplicate %d", l.Table)
		}
		tables[l.Table] = true
		if l.FwMark == 0 || l.FwMark&^LinkMarkMask != 0 {
			p.add(f+".fwmark", "%#x must be non-zero and fit mask %#x", l.FwMark, LinkMarkMask)
		}
		if marks[l.FwMark] {
			p.add(f+".fwmark", "duplicate %#x", l.FwMark)
		}
		marks[l.FwMark] = true
		for _, a := range l.ProbeTargets {
			if !a.Is4() {
				p.add(f+".probe_targets", "%s: only IPv4 is supported", a)
			}
		}
		if l.SQM.DownMbit < 0 || l.SQM.UpMbit < 0 {
			p.add(f+".sqm", "bandwidth must not be negative")
		}
		if err := l.SQM.Params(l.Kind).Validate(); err != nil {
			p.add(f+".sqm", "%v", err)
		}
		if q := l.Quota; q != nil {
			if q.MonthlyGB <= 0 {
				p.add(f+".quota.monthly_gb", "must be positive")
			}
			if q.ResetDay < 1 || q.ResetDay > 28 {
				p.add(f+".quota.reset_day", "want 1..28, got %d", q.ResetDay)
			}
		}
	}
}

func (c *Config) validateMonitor(p *problems) {
	m := c.Monitor
	for _, a := range m.Targets {
		if !a.Is4() {
			p.add("monitor.targets", "%s: only IPv4 is supported", a)
		}
	}
	if m.Interval <= 0 {
		p.add("monitor.interval", "must be positive")
	}
	if m.Timeout <= 0 || m.Timeout > m.Interval {
		p.add("monitor.timeout", "must be positive and not exceed interval")
	}
	if m.Window < 1 || m.FailAfter < 1 || m.RecoverAfter < 1 {
		p.add("monitor", "window, fail_after and recover_after must be >= 1")
	}
	for _, a := range m.WhitelistTargets {
		if !a.Is4() {
			p.add("monitor.whitelist_targets", "%s: only IPv4 is supported", a)
		}
	}
	if len(m.TCPTargets) == 0 {
		p.add("monitor.tcp_targets", "at least one target is required")
	}
	for _, a := range m.TCPTargets {
		if !a.Addr().Is4() || a.Port() == 0 {
			p.add("monitor.tcp_targets", "%s: want IPv4:port", a)
		}
	}
	for i, s := range m.SpeedTest.URLs {
		if !httpURL(s) {
			p.add(fmt.Sprintf("monitor.speedtest.urls[%d]", i), "want http(s) URL, got %q", s)
		}
	}
	h := m.HTTPCheck
	if *h.Enabled {
		if h.Interval < m.Interval || h.Timeout <= 0 || h.FailAfter < 1 {
			p.add("monitor.http_check", "need interval >= monitor.interval, timeout > 0, fail_after >= 1")
		}
		foreign := 0
		for i, u := range h.URLs {
			f := fmt.Sprintf("monitor.http_check.urls[%d]", i)
			switch {
			case !httpURL(u.URL):
				p.add(f, "want http(s) URL, got %q", u.URL)
			case u.Domestic && !strings.HasPrefix(u.URL, "https://"):
				// По http страница авторизации ответит тем же, что и настоящий сайт.
				p.add(f, "domestic check must use https, got %q", u.URL)
			case u.Status == 0 && !u.Domestic, u.Status != 0 && (u.Status < 100 || u.Status > 599):
				p.add(f, "want HTTP status (0 — any — only for domestic), got %d", u.Status)
			}
			if !u.Domestic {
				foreign++
			}
		}
		if foreign == 0 {
			p.add("monitor.http_check.urls", "at least one non-domestic URL is required")
		}
	}
	if _, _, ok := m.SpeedTest.AtClock(); !ok {
		p.add("monitor.speedtest.at", "want HH:MM, got %q", m.SpeedTest.At)
	}
	if m.SpeedTest.Duration <= 0 || m.SpeedTest.MaxBytes <= 0 {
		p.add("monitor.speedtest", "duration and max_bytes must be positive")
	}
	for i, l := range c.Links {
		if general, _ := c.ProbeTargets(l); len(general) == 0 {
			p.add(fmt.Sprintf("links[%d]", i), "no general probe targets left after excluding whitelist_targets")
		}
	}
}

func httpURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Host != "" && (u.Scheme == "http" || u.Scheme == "https")
}

func (c *Config) linkExists(id model.LinkID) bool {
	return slices.ContainsFunc(c.Links, func(l Link) bool { return l.ID == id })
}

func (c *Config) classExists(id model.TrafficClass) bool {
	return slices.ContainsFunc(c.Classes, func(cl Class) bool { return cl.ID == id })
}

func (c *Config) validateClasses(p *problems) {
	seen := map[model.TrafficClass]bool{}
	for i, cl := range c.Classes {
		f := fmt.Sprintf("classes[%d]", i)
		if !classIDRe.MatchString(string(cl.ID)) {
			p.add(f+".id", "%q: want [a-z0-9][a-z0-9_-]{0,31}", cl.ID)
		}
		if seen[cl.ID] {
			p.add(f+".id", "duplicate %q", cl.ID)
		}
		seen[cl.ID] = true
		if err := cl.Policy.Validate(); err != nil {
			p.add(f, "%v", err)
		}
		for _, id := range slices.Concat(cl.Links, cl.Fallback) {
			if !c.linkExists(id) {
				p.add(f, "unknown link %q", id)
			}
		}
	}
	if !seen[model.ClassDefault] {
		p.add("classes", "class %q is required", model.ClassDefault)
	}
}

func (c *Config) validateClassify(p *problems) {
	names := map[string]bool{}
	for i, r := range c.Classify.Rules {
		f := fmt.Sprintf("classify.rules[%d]", i)
		if r.Name == "" || names[r.Name] {
			p.add(f+".name", "empty or duplicate name %q", r.Name)
		}
		names[r.Name] = true
		if !c.classExists(r.Class) {
			p.add(f+".class", "unknown class %q", r.Class)
		}
		if err := r.Match.Validate(); err != nil {
			p.add(f, "%v", err)
		}
		for _, d := range r.Devices {
			if d.IsZero() {
				p.add(f+".devices", "empty device")
			}
		}
	}
	builtin, err := profile.Builtin()
	if err != nil {
		p.add("classify.services", "builtin catalog: %v", err)
		return
	}
	if err := builtin.WithUser(c.Classify.Services).Validate(); err != nil {
		p.add("classify.services", "%v", err)
	}
	// Своим профилям — только настроенные классы; встроенный каталог может
	// ссылаться на класс без политики — такие части идут по default.
	for _, s := range c.Classify.Services {
		for _, part := range s.Parts {
			if !c.classExists(part.Class) {
				p.add("classify.services", "%s/%s: unknown class %q", s.ID, part.ID, part.Class)
			}
		}
	}
}

func (c *Config) validateDNS(p *problems) {
	d := c.DNS
	if len(d.Listen) == 0 {
		p.add("dns.listen", "at least one address is required")
	}
	for _, l := range d.Listen {
		if err := ipv4HostPort(l); err != nil {
			p.add("dns.listen", "%v", err)
		}
	}
	for i, u := range d.Upstreams {
		pu, err := url.Parse(u.URL)
		if err != nil || pu.Host == "" || pu.Scheme != "https" && pu.Scheme != "tls" {
			p.add(fmt.Sprintf("dns.upstreams[%d].url", i), "want https://host/path (DoH) or tls://host (DoT), got %q", u.URL)
		}
		if u.TLSName != "" {
			if n, err := lists.NormalizeName(u.TLSName); err != nil || n != u.TLSName || !strings.Contains(n, ".") {
				p.add(fmt.Sprintf("dns.upstreams[%d].tls_name", i), "want a lowercase host name, got %q", u.TLSName)
			}
		}
	}
	for _, a := range d.Bootstrap {
		if !a.Is4() {
			p.add("dns.bootstrap", "%s: only IPv4 is supported", a)
		}
	}
	if d.CacheSize < 0 {
		p.add("dns.cache_size", "must not be negative")
	}
	if d.SetTTL.Min <= 0 || d.SetTTL.Max < d.SetTTL.Min {
		p.add("dns.set_ttl", "want 0 < min <= max")
	}
	if d.Watchdog.Interval <= 0 || d.Watchdog.Failures < 1 {
		p.add("dns.watchdog", "interval must be positive and failures >= 1")
	}
	if _, err := coredns.NewPolicy(d.PolicyUpstreams(), nil, coredns.NewHealth(coredns.DefaultHealthParams()), d.PolicyParams()); err != nil {
		p.add("dns.upstreams", "%v", err)
	}
	cat, err := profile.Builtin()
	if err == nil {
		cat = cat.WithUser(c.Classify.Services)
	}
	for _, s := range d.Sensitive.Services {
		if _, ok := cat.Domains(s); !ok {
			p.add("dns.sensitive.services", "unknown service or part %q", s)
		}
	}
	if d.Fallback.IsValid() {
		if !d.Fallback.Addr().Is4() {
			p.add("dns.fallback", "%s: only IPv4 is supported", d.Fallback)
		}
		if slices.Contains(d.Listen, d.Fallback.String()) {
			p.add("dns.fallback", "%s is the daemon's own listen address", d.Fallback)
		}
	}
	for name, a := range d.Hosts {
		if n, err := lists.NormalizeName(name); err != nil || n != name {
			p.add("dns.hosts", "%q: want a normalized name (lowercase, punycode)", name)
		}
		if !a.Is4() {
			p.add("dns.hosts", "%s: %s is not an IPv4 address", name, a)
		}
	}
	seenDev := map[string]bool{}
	for i, dev := range d.Devices {
		f := fmt.Sprintf("dns.devices[%d]", i)
		if dev.Address.IsZero() {
			p.add(f+".address", "required: an IPv4 address, a MAC or a device id")
		}
		if seenDev[dev.Address.String()] {
			p.add(f+".address", "duplicate %s", dev.Address)
		}
		seenDev[dev.Address.String()] = true
		if !dev.Mode.Valid() {
			p.add(f+".mode", "want observe, redirect, block or exempt, got %q", dev.Mode)
		}
	}
	for _, s := range d.Sensitive.Domains {
		if n, err := lists.NormalizeName(s); err != nil || n != s {
			p.add("dns.sensitive.domains", "%q: want a normalized domain (lowercase, punycode)", s)
		}
	}
}

// PolicyParams — настройки выбора серверов для core/dns.
func (d DNS) PolicyParams() coredns.Params {
	p := coredns.DefaultParams()
	p.Race = d.Race
	p.SensitiveFallback = d.Sensitive.FallbackFast
	return p
}

// PolicyUpstreams — серверы для core/dns.
func (d DNS) PolicyUpstreams() []coredns.Upstream {
	out := make([]coredns.Upstream, len(d.Upstreams))
	for i, u := range d.Upstreams {
		out[i] = coredns.Upstream{Name: u.Name, Pools: u.Pools, Backup: u.Backup}
	}
	return out
}

func (c *Config) validateLists(p *problems) {
	if c.Lists.UpdateInterval <= 0 {
		p.add("lists.update_interval", "must be positive")
	}
	seen := map[string]bool{}
	for i, s := range c.Lists.Sources {
		f := fmt.Sprintf("lists.sources[%d]", i)
		if !sourceIDRe.MatchString(s.ID) {
			p.add(f+".id", "%q: want [a-z0-9][a-z0-9_.-]{0,63}", s.ID)
		}
		if seen[s.ID] {
			p.add(f+".id", "duplicate %q", s.ID)
		}
		seen[s.ID] = true
		if u, err := url.Parse(s.URL); err != nil || u.Host == "" || u.Scheme != "https" && u.Scheme != "http" {
			p.add(f+".url", "want http(s) URL, got %q", s.URL)
		}
		if !s.Format.Valid() {
			p.add(f+".format", "want text or geosite, got %q", s.Format)
		}
		if s.Format == lists.FormatGeosite && len(s.Categories) == 0 {
			p.add(f+".categories", "required for geosite format")
		}
		switch s.Purpose {
		case lists.PurposeBypass, lists.PurposeNever, lists.PurposeInside:
			if s.Class != "" {
				p.add(f+".class", "only allowed with purpose class")
			}
		case lists.PurposeClass:
			if !c.classExists(s.Class) {
				p.add(f+".class", "unknown class %q", s.Class)
			}
		default:
			p.add(f+".purpose", "want bypass, class, never or inside, got %q", s.Purpose)
		}
		if s.Interval < 0 {
			p.add(f+".interval", "must not be negative")
		}
		if s.Checksum != "" {
			if u, err := url.Parse(s.Checksum); err != nil || u.Host == "" || u.Scheme != "https" && u.Scheme != "http" {
				p.add(f+".checksum", "want http(s) URL, got %q", s.Checksum)
			}
		}
	}
	for i, r := range c.Lists.Manual {
		f := fmt.Sprintf("lists.manual[%d]", i)
		if len(r.Domains) == 0 {
			p.add(f+".domains", "at least one domain is required")
		}
		for _, d := range r.Domains {
			if n, err := lists.NormalizeName(d); err != nil || n != d {
				p.add(f+".domains", "%q: want a normalized domain (lowercase, punycode)", d)
			}
		}
		switch r.Purpose {
		case lists.PurposeBypass, lists.PurposeNever, lists.PurposeInside:
			if r.Class != "" {
				p.add(f+".class", "only allowed with purpose class")
			}
		case lists.PurposeClass:
			if !c.classExists(r.Class) {
				p.add(f+".class", "unknown class %q", r.Class)
			}
		default:
			p.add(f+".purpose", "want bypass, class, never or inside, got %q", r.Purpose)
		}
	}
}

func (c *Config) validateDPI(p *problems) {
	d := c.DPI
	if !d.Enabled {
		return
	}
	if !path.IsAbs(d.NFQWS) {
		p.add("dpi.nfqws", "want an absolute path, got %q", d.NFQWS)
	}
	if !path.IsAbs(d.LuaDir) {
		p.add("dpi.lua_dir", "want an absolute path, got %q", d.LuaDir)
	}
	if !path.IsAbs(d.Dir) {
		p.add("dpi.dir", "want an absolute path, got %q", d.Dir)
	}
	known := map[model.LinkID]bool{}
	for _, l := range c.Links {
		known[l.ID] = true
	}
	for _, l := range d.Links {
		if !known[l] {
			p.add("dpi.links", "unknown link %q", l)
		}
	}
	for _, r := range d.AllowRisks {
		if r != coredpi.RiskTS && r != coredpi.RiskSYN {
			p.add("dpi.allow_risks", "unknown risk %q (want ts, syn)", r)
		}
	}
	if int(d.QueueBase)+len(c.Links) > 65536 {
		p.add("dpi.queue_base", "queues for all links must fit 0..65535")
	}
	if d.RecheckInterval <= 0 {
		p.add("dpi.recheck_interval", "must be positive")
	}
	for _, dom := range d.ProbeDomains {
		if n, err := model.NormalizeDomain(dom); err != nil || n != dom {
			p.add("dpi.probe_domains", "%q is not a normalized domain", dom)
		}
	}
}

func (c *Config) validateProxy(p *problems) {
	x := c.Proxy
	if x.Engine != "mihomo" {
		p.add("proxy.engine", "only mihomo is supported, got %q", x.Engine)
	}
	// API ядра даёт управление соединениями — наружу его не открываем.
	host, _, err := net.SplitHostPort(x.Controller)
	if a, perr := netip.ParseAddr(host); err != nil || perr != nil || !a.IsLoopback() {
		p.add("proxy.controller", "must be a loopback address with port, got %q", x.Controller)
	}
	if x.Enabled {
		if x.Binary == "" {
			p.add("proxy.binary", "required when proxy is enabled")
		}
		if x.Version == "" {
			p.add("proxy.version", "pin the expected core version")
		}
	}
	if x.TProxyPortBase < 1024 {
		p.add("proxy.tproxy_port_base", "must be >= 1024")
	}
	if m := x.RoutingMarkBase; m == 0 || m&LinkMarkMask != 0 || m&zapretMark != 0 || m&TinMarkMask != 0 {
		p.add("proxy.routing_mark_base", "%#x must not overlap link marks %#x, CAKE tin marks %#x or zapret mark %#x", m, LinkMarkMask, TinMarkMask, zapretMark)
	}
}
