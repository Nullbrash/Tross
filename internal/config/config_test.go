package config

import (
	"strings"
	"testing"
	"time"

	"tross/core/model"
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
	if cfg.Monitor.Interval != 2*time.Second || len(cfg.DNS.Upstreams) != 3 {
		t.Error("monitor/dns defaults not applied")
	}
	if cfg.Proxy.WorkDir != "/var/lib/tross/mihomo" {
		t.Errorf("proxy work_dir = %q", cfg.Proxy.WorkDir)
	}
	if !*cfg.DNS.FirefoxCanaryNXDomain || cfg.Devices.DefaultDNSMode != model.DNSObserve {
		t.Error("dns/devices defaults not applied")
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
