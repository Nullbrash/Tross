package config

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"tross/core/model"
	"tross/internal/dataplane"
)

const minimal = `
lan:
  interface: br0
  networks: [192.168.1.0/24]
links:
  - { id: isp1, kind: wired, interface: eth1 }
  - { id: lte, kind: lte, interface: eth2 }
dns:
  listen: ["192.168.1.1:53"]
`

func TestLoadExample(t *testing.T) {
	cfg, err := Load("../../configs/example.yaml")
	if err != nil {
		t.Fatalf("example config must be valid: %v", err)
	}
	if !cfg.Daemon.DryRun {
		t.Error("example must default to dry_run so it is safe on a dev machine")
	}
	if len(cfg.Links) != 3 {
		t.Fatalf("links = %d, want 3", len(cfg.Links))
	}
	lte := cfg.Links[2]
	if lte.Table != 103 || lte.FwMark != 0x300 || !lte.Model().Metered {
		t.Errorf("lte derived table/mark/metered wrong: %d %#x %v", lte.Table, lte.FwMark, lte.Model().Metered)
	}
	if lte.GatewayAddr().String() != "192.168.8.1" {
		t.Errorf("lte gateway = %v", lte.GatewayAddr())
	}
	pol := cfg.Policies()
	bulk, ok := pol[model.ClassBulk]
	if !ok || len(bulk.Fallback) != 0 || len(bulk.Links) != 2 {
		t.Errorf("bulk policy must exclude LTE entirely: %+v", bulk)
	}
	if g := pol[model.ClassGaming]; g.StickyTTL != 2*time.Hour || g.Selector != model.SelectLowestLatency {
		t.Errorf("gaming policy decoded wrong: %+v", g)
	}
	if cfg.Proxy.RoutingMarkBase != 0x10000 {
		t.Errorf("hex routing mark decoded as %#x", cfg.Proxy.RoutingMarkBase)
	}
}

func TestDefaults(t *testing.T) {
	cfg, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Links[0].Table != 101 || cfg.Links[0].FwMark != 0x100 || cfg.Links[0].Gateway != "auto" {
		t.Errorf("isp1 defaults: %+v", cfg.Links[0])
	}
	if cfg.Links[0].Model().Metered || !cfg.Links[1].Model().Metered {
		t.Error("metered must default to true only for lte")
	}
	if len(cfg.Classes) != 1 || cfg.Classes[0].ID != model.ClassDefault || cfg.Classes[0].Method != model.MethodAuto {
		t.Errorf("implicit default class: %+v", cfg.Classes)
	}
	if got := len(cfg.API.AllowedNetworks); got != 2 {
		t.Errorf("allowed networks = %d, want loopback + LAN", got)
	}
	if cfg.Monitor.Interval != 2*time.Second || len(cfg.DNS.Upstreams) != len(DefaultUpstreams()) || len(cfg.Monitor.TCPTargets) != 3 || len(cfg.Monitor.WhitelistTargets) != 3 {
		t.Error("monitor/dns defaults not applied")
	}
	if cfg.DNS.Race != 2 || len(cfg.DNS.Sensitive.Services) == 0 || len(cfg.DNS.Sensitive.Domains) == 0 {
		t.Errorf("dns race/sensitive defaults: %d %+v", cfg.DNS.Race, cfg.DNS.Sensitive)
	}
	if cfg.Proxy.WorkDir != "/var/lib/tross/mihomo" {
		t.Errorf("proxy work_dir = %q", cfg.Proxy.WorkDir)
	}
	if !*cfg.DNS.FirefoxCanaryNXDomain || cfg.Devices.DefaultDNSMode != model.DNSRedirect {
		t.Error("dns/devices defaults not applied")
	}
	if cfg.DNS.Fallback.String() != "192.168.1.1:5335" {
		t.Errorf("fallback resolver = %s, want the listen address, port 5335", cfg.DNS.Fallback)
	}
	// -data-dir переносит и выведенные из каталога умолчания.
	cfg.SetDataDir("/srv/tross")
	if cfg.Daemon.DataDir != "/srv/tross" || cfg.Proxy.WorkDir != "/srv/tross/mihomo" {
		t.Errorf("after SetDataDir: data_dir %q, work_dir %q", cfg.Daemon.DataDir, cfg.Proxy.WorkDir)
	}
}

func TestSetDataDirKeepsExplicitWorkDir(t *testing.T) {
	cfg, err := Parse([]byte(strings.Replace(minimal, "links:", "proxy: { work_dir: /opt/mihomo }\nlinks:", 1)))
	if err != nil {
		t.Fatal(err)
	}
	cfg.SetDataDir("/srv/tross")
	if cfg.Proxy.WorkDir != "/opt/mihomo" {
		t.Errorf("explicit work_dir must stay, got %q", cfg.Proxy.WorkDir)
	}
}

func TestLoadLabConfig(t *testing.T) {
	cfg, err := Load("../../configs/lab.yaml")
	if err != nil {
		t.Fatalf("lab config must be valid: %v", err)
	}
	g, wl := cfg.ProbeTargets(cfg.Links[2])
	if len(g) != 2 || len(wl) != 1 || wl[0].String() != "203.0.113.3" {
		t.Fatalf("lte targets: general %v, whitelist %v", g, wl)
	}
	// Распознавание белых списков по умолчанию включено у всех каналов.
	g, wl = cfg.ProbeTargets(cfg.Links[0])
	if len(g) != 2 || len(wl) != 1 {
		t.Fatalf("isp1 targets with default whitelist detection: %v %v", g, wl)
	}
	off := cfg.Links[0]
	off.WhitelistDetection = ptr(false)
	if g, wl = cfg.ProbeTargets(off); len(g) != 3 || wl != nil {
		t.Fatalf("detection off must probe all targets: %v %v", g, wl)
	}
}

func TestSpeedTestValidation(t *testing.T) {
	cfg, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatal(err)
	}
	if h, m, ok := cfg.Monitor.SpeedTest.AtClock(); !ok || h != 4 || m != 0 {
		t.Fatalf("default speedtest.at = %d:%d %v", h, m, ok)
	}
	if _, err := Parse([]byte(minimal + "monitor: { speedtest: { at: '25:00' } }\n")); err == nil || !strings.Contains(err.Error(), "speedtest.at") {
		t.Fatalf("bad time must fail, got %v", err)
	}
	only := minimal + "monitor: { targets: [77.88.8.8], whitelist_targets: [77.88.8.8] }\n"
	if _, err := Parse([]byte(only)); err == nil || !strings.Contains(err.Error(), "no general probe targets") {
		t.Fatalf("whitelist-only targets must fail, got %v", err)
	}
}

func TestHTTPCheckDomesticRules(t *testing.T) {
	bad := map[string]string{
		"domestic over http": "monitor: { http_check: { urls: [{ url: 'http://cp.cloudflare.com/generate_204', status: 204 }, { url: 'http://ya.ru/', domestic: true }] } }\n",
		"any-status abroad":  "monitor: { http_check: { urls: [{ url: 'https://example.com/' }] } }\n",
		"only domestic":      "monitor: { http_check: { urls: [{ url: 'https://ya.ru/', domestic: true }] } }\n",
	}
	for name, y := range bad {
		if _, err := Parse([]byte(minimal + y)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	cfg, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatal(err)
	}
	dom := 0
	for _, u := range cfg.Monitor.HTTPCheck.URLs {
		if u.Domestic {
			dom++
		}
	}
	if dom == 0 {
		t.Error("defaults must include a domestic HTTPS check")
	}
}

func TestLinkMarkMaskMatchesDataplane(t *testing.T) {
	if LinkMarkMask != dataplane.LinkMarkMask {
		t.Fatalf("config %#x != dataplane %#x: link marks would not match ip rules", LinkMarkMask, dataplane.LinkMarkMask)
	}
}

func TestUnknownFieldRejected(t *testing.T) {
	_, err := Parse([]byte(minimal + "\nmonitr: {interval: 1s}\n"))
	if err == nil || !strings.Contains(err.Error(), "monitr") {
		t.Fatalf("typo in field name must fail, got %v", err)
	}
}

func TestValidationErrors(t *testing.T) {
	cases := map[string]struct {
		yaml string
		want string
	}{
		"duplicate link": {
			yaml: strings.Replace(minimal, "id: lte", "id: isp1", 1),
			want: `duplicate "isp1"`,
		},
		"bad link id": {
			yaml: strings.Replace(minimal, "id: lte", "id: LTE", 1),
			want: "links[1].id",
		},
		"lan interface as wan": {
			yaml: strings.Replace(minimal, "interface: eth2", "interface: br0", 1),
			want: "is the LAN interface",
		},
		"unknown link in class": {
			yaml: minimal + "classes:\n  - { id: default, links: [isp9] }\n",
			want: `unknown link "isp9"`,
		},
		"missing default class": {
			yaml: minimal + "classes:\n  - { id: gaming }\n",
			want: `class "default" is required`,
		},
		"reserved table": {
			yaml: strings.Replace(minimal, "interface: eth1 }", "interface: eth1, table: 254 }", 1),
			want: "reserved",
		},
		"mark outside mask": {
			yaml: strings.Replace(minimal, "interface: eth1 }", "interface: eth1, fwmark: 0x10000 }", 1),
			want: "fwmark",
		},
		"plain dns upstream": {
			yaml: minimal + "  upstreams: [{ name: x, url: 'udp://8.8.8.8' }]\n",
			want: "dns.upstreams[0].url",
		},
		"public controller": {
			yaml: minimal + "proxy: { controller: '0.0.0.0:9090' }\n",
			want: "proxy.controller",
		},
		"enabled proxy without pinned version": {
			yaml: minimal + "proxy: { enabled: true }\n",
			want: "proxy.version",
		},
		"geosite without categories": {
			yaml: minimal + "lists:\n  sources:\n    - { id: g, url: 'https://x/dlc.dat', format: geosite }\n",
			want: "categories",
		},
		"class list with unknown class": {
			yaml: minimal + "lists:\n  sources:\n    - { id: g, url: 'https://x/a.lst', format: text, purpose: class, class: video }\n",
			want: `unknown class "video"`,
		},
		"no links": {
			yaml: "lan: { interface: br0, networks: [10.0.0.0/24] }\ndns: { listen: ['10.0.0.1:53'] }\n",
			want: "at least one link",
		},
		"ipv6 lan": {
			yaml: strings.Replace(minimal, "192.168.1.0/24", "fd00::/64", 1),
			want: "only IPv4",
		},
		"ipv6 api listen": {
			yaml: minimal + "api: { listen: '[::1]:8080' }\n",
			want: "api.listen",
		},
		"api listen on all addresses": {
			yaml: minimal + "api: { listen: ':8080' }\n",
			want: "api.listen",
		},
		"ipv6 allowed network": {
			yaml: minimal + "api: { allowed_networks: ['::1/128'] }\n",
			want: "api.allowed_networks",
		},
		"ipv6 dns listen": {
			yaml: strings.Replace(minimal, `"192.168.1.1:53"`, `"[fd00::1]:53"`, 1),
			want: "dns.listen",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(c.yaml))
			if err == nil {
				t.Fatalf("expected error containing %q", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not contain %q", err, c.want)
			}
		})
	}
}

func TestApplyFlags(t *testing.T) {
	parse := func() *Config {
		cfg, err := Parse([]byte(minimal))
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	cfg := parse()
	cfg.ApplyFlags(true, "")
	if !cfg.Daemon.DryRun || cfg.Daemon.DataDir != "" {
		t.Errorf("dry run without -data-dir must keep the store in memory: %+v", cfg.Daemon)
	}
	cfg = parse()
	cfg.ApplyFlags(true, "bin/data")
	if cfg.Daemon.DataDir != "bin/data" {
		t.Errorf("explicit -data-dir: %+v", cfg.Daemon)
	}
	cfg = parse()
	cfg.ApplyFlags(false, "")
	if cfg.Daemon.DryRun || cfg.Daemon.DataDir != "/var/lib/tross" {
		t.Errorf("real mode keeps data_dir: %+v", cfg.Daemon)
	}
}

func TestHTTPCheckDNSServers(t *testing.T) {
	cfg, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatal(err)
	}
	// По умолчанию — DoH: открытый DNS на 53 к сторонним серверам бывает закрыт.
	for _, d := range cfg.Monitor.HTTPCheck.DNS {
		if d.Proto != DNSOverHTTPS || d.Addr.Port() != 443 || d.URL == "" {
			t.Errorf("default http_check.dns %q = %+v, want DoH", d, d)
		}
	}

	good := map[string]DNSServer{
		"1.1.1.1":                        {Proto: DNSPlain, Addr: netip.MustParseAddrPort("1.1.1.1:53")},
		"udp://9.9.9.9:5353":             {Proto: DNSPlain, Addr: netip.MustParseAddrPort("9.9.9.9:5353")},
		"tls://1.1.1.1":                  {Proto: DNSOverTLS, Addr: netip.MustParseAddrPort("1.1.1.1:853")},
		"https://8.8.4.4/dns-query":      {Proto: DNSOverHTTPS, Addr: netip.MustParseAddrPort("8.8.4.4:443"), URL: "https://8.8.4.4/dns-query"},
		"https://9.9.9.9:8443/dns-query": {Proto: DNSOverHTTPS, Addr: netip.MustParseAddrPort("9.9.9.9:8443"), URL: "https://9.9.9.9:8443/dns-query"},
	}
	for s, want := range good {
		got, err := ParseDNSServer(s)
		if err != nil || got.Proto != want.Proto || got.Addr != want.Addr || got.URL != want.URL {
			t.Errorf("ParseDNSServer(%q) = %+v, %v; want %+v", s, got, err, want)
		}
	}
	for _, s := range []string{
		"dns.google",                    // имя: проверке нельзя зависеть от DNS
		"https://dns.google/dns-query",  // то же
		"https://1.1.1.1",               // DoH без пути
		"tls://1.1.1.1/dns-query",       // путь только у https
		"2606:4700:4700::1111",          // IPv6 не поддерживается
		"quic://1.1.1.1",                // неизвестный способ
		"https://u:p@1.1.1.1/dns-query", // учётные данные в адресе
	} {
		if _, err := ParseDNSServer(s); err == nil {
			t.Errorf("ParseDNSServer(%q) accepted", s)
		}
	}

	y := minimal + "monitor: { http_check: { dns: [1.1.1.1, 'tls://8.8.4.4', 'https://9.9.9.9/dns-query'] } }\n"
	cfg, err = Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	if d := cfg.Monitor.HTTPCheck.DNS; len(d) != 3 || d[0].Proto != DNSPlain || d[1].Proto != DNSOverTLS || d[2].Proto != DNSOverHTTPS {
		t.Fatalf("parsed http_check.dns = %+v", d)
	}
	if _, err := Parse([]byte(minimal + "monitor: { http_check: { dns: [dns.google] } }\n")); err == nil || !strings.Contains(err.Error(), "not a name") {
		t.Fatalf("name in http_check.dns: err = %v", err)
	}
}

func TestClassifySection(t *testing.T) {
	y := minimal + `classes:
  - { id: default }
  - { id: bulk, links: [isp1] }
classify:
  rules:
    - { name: pc-torrent, class: bulk, devices: [192.168.1.20], proto: tcp, ports: ["51413"] }
  services:
    - { id: steam, disabled: true }
    - { id: myserver, parts: [{ id: mc, class: default, match: [{ proto: tcp, ports: ["25570"] }] }] }
`
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	if r := cfg.Classify.Rules[0]; r.Class != model.ClassBulk || len(r.Devices) != 1 || r.Ports[0].From != 51413 {
		t.Fatalf("rule = %+v", r)
	}
	bad := map[string]string{
		"unknown class":         "classify: { rules: [{ name: x, class: gaming, ports: ['1'] }] }\n",
		"whole protocol":        "classify: { rules: [{ name: x, class: default, proto: tcp }] }\n",
		"ipv6 device":           "classify: { rules: [{ name: x, class: default, devices: ['::1'], ports: ['1'] }] }\n",
		"duplicate name":        "classify: { rules: [{ name: x, class: default, ports: ['1'] }, { name: x, class: default, ports: ['2'] }] }\n",
		"service unknown class": "classify: { services: [{ id: s, parts: [{ id: p, class: gaming, match: [{ ports: ['1'] }] }] }] }\n",
	}
	for name, extra := range bad {
		if _, err := Parse([]byte(minimal + extra)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestInboundSection(t *testing.T) {
	y := minimal + `inbound:
  forwards:
    - { name: mc, port: 25565, to: 192.168.1.50, links: [isp1] }
    - { name: game, proto: both, port: "27015-27030", to: 192.168.1.51 }
    - { name: mc-lte, port: 25565, to: 192.168.1.50, to_port: 25570, links: [lte] }
`
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	f := cfg.Inbound.Forwards
	if f[0].Proto != "tcp" || f[0].Port.From != 25565 || len(f[1].Protos()) != 2 || f[1].Port.To != 27030 || f[2].ToPort != 25570 {
		t.Fatalf("forwards = %+v", f)
	}
	if g := cfg.Inbound.Guard; g.NewPerMinute != 20 || g.Burst != 20 || g.MaxConnections != 32 {
		t.Errorf("guard defaults = %+v", g)
	}
	bad := map[string]string{
		"outside LAN":     "inbound: { forwards: [{ name: x, port: 1, to: 10.0.0.5 }] }\n",
		"no port":         "inbound: { forwards: [{ name: x, to: 192.168.1.5 }] }\n",
		"range to_port":   "inbound: { forwards: [{ name: x, port: '10-20', to: 192.168.1.5, to_port: 80 }] }\n",
		"bad proto":       "inbound: { forwards: [{ name: x, proto: icmp, port: 1, to: 192.168.1.5 }] }\n",
		"unknown link":    "inbound: { forwards: [{ name: x, port: 1, to: 192.168.1.5, links: [isp9] }] }\n",
		"duplicate name":  "inbound: { forwards: [{ name: x, port: 1, to: 192.168.1.5 }, { name: x, port: 2, to: 192.168.1.5 }] }\n",
		"overlap on link": "inbound: { forwards: [{ name: x, port: '10-20', to: 192.168.1.5 }, { name: y, proto: both, port: 15, to: 192.168.1.6, links: [isp1] }] }\n",
		"zero guard":      "inbound: { guard: { max_connections: -1 } }\n",
	}
	for name, extra := range bad {
		if _, err := Parse([]byte(minimal + extra)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Тот же порт, но другой протокол или другой канал — не пересечение.
	ok := "inbound: { forwards: [{ name: x, port: 15, to: 192.168.1.5 }, { name: y, proto: udp, port: 15, to: 192.168.1.6 }] }\n"
	if _, err := Parse([]byte(minimal + ok)); err != nil {
		t.Errorf("tcp and udp on one port: %v", err)
	}
}

// Стенд с классами — тот же стенд: расходиться с lab.yaml он может только
// классами, правилами и пробросами, иначе тесты классов шли бы в другой сети.
func TestLabClassesMatchesLab(t *testing.T) {
	lab, err := Load("../../configs/lab.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cls, err := Load("../../configs/lab-classes.yaml")
	if err != nil {
		t.Fatalf("lab-classes config must be valid: %v", err)
	}
	if len(cls.Classes) < 5 || len(cls.Classify.Rules) == 0 || len(cls.Inbound.Forwards) == 0 {
		t.Fatalf("lab-classes: classes %d, rules %d, forwards %d", len(cls.Classes), len(cls.Classify.Rules), len(cls.Inbound.Forwards))
	}
	cls.Classes, cls.Classify, cls.Inbound = lab.Classes, lab.Classify, lab.Inbound
	if !reflect.DeepEqual(lab, cls) {
		t.Error("configs/lab-classes.yaml differs from configs/lab.yaml outside classes, classify and inbound")
	}
}

func TestSQMPercents(t *testing.T) {
	y := `
lan: { interface: br0, networks: [192.168.1.0/24] }
links:
  - { id: isp1, kind: wired, interface: eth1 }
  - { id: lte, kind: lte, interface: eth2, sqm: { min_pct: 40, auto: false } }
dns: { listen: ["192.168.1.1:53"] }
`
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	w, l := cfg.Links[0].SQM.Params(model.LinkKindWired), cfg.Links[1].SQM.Params(model.LinkKindLTE)
	if w.Start != 0.90 || w.Min != 0.80 || w.Max != 0.97 || !w.Auto {
		t.Errorf("wired defaults: %+v", w)
	}
	if l.Start != 0.90 || l.Min != 0.40 || l.Max != 0.95 || l.Auto {
		t.Errorf("lte with overrides: %+v", l)
	}
	for name, sqm := range map[string]string{
		"start below min": "{ start_pct: 70 }",
		"max over 100":    "{ max_pct: 120 }",
		"min over max":    "{ min_pct: 98, start_pct: 98 }",
	} {
		bad := "lan: { interface: br0, networks: [192.168.1.0/24] }\nlinks:\n  - { id: isp1, kind: wired, interface: eth1, sqm: " + sqm + " }\ndns: { listen: [\"192.168.1.1:53\"] }\n"
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
