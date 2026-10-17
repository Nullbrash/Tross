package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestDNSValidation(t *testing.T) {
	for name, tc := range map[string]struct{ yaml, want string }{
		"unknown backup": {
			yaml: minimal + "  upstreams: [{ name: a, url: 'https://1.1.1.1/dns-query', pools: [protected, fast], backup: zz }]\n",
			want: "unknown backup",
		},
		"no protected pool": {
			yaml: minimal + "  upstreams: [{ name: a, url: 'https://1.1.1.1/dns-query', pools: [fast] }]\n",
			want: "both protected and fast",
		},
		"bad pool": {
			yaml: minimal + "  upstreams: [{ name: a, url: 'https://1.1.1.1/dns-query', pools: [protected, fast, slow] }]\n",
			want: "unknown pool",
		},
		"unknown sensitive service": {
			yaml: minimal + "  sensitive: { services: [stem] }\n",
			want: "dns.sensitive.services",
		},
		"unknown sensitive part": {
			yaml: minimal + "  sensitive: { services: [steam/shop] }\n",
			want: "dns.sensitive.services",
		},
		"sensitive domain not normalized": {
			yaml: minimal + "  sensitive: { domains: [Telegram.org] }\n",
			want: "dns.sensitive.domains",
		},
		"mrs format": {
			yaml: minimal + "lists:\n  sources:\n    - { id: m, url: 'https://x/y.mrs', format: mrs }\n",
			want: "want text or geosite",
		},
	} {
		_, err := Parse([]byte(tc.yaml))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
	ok := minimal + "  sensitive: { services: [steam/store], domains: [telegram.org] }\n" +
		"lists:\n  sources:\n    - { id: i, url: 'https://x/geosite.dat', format: geosite, categories: [ru-available-only-inside], purpose: inside }\n" +
		"    - { id: n, url: 'https://x/n.lst', format: text, purpose: never, disabled: true }\n"
	if _, err := Parse([]byte(ok)); err != nil {
		t.Errorf("valid dns/lists rejected: %v", err)
	}
}

// Пример конфига повторяет умолчания: иначе пример обещал бы одно, а без
// раздела dns демон делал бы другое.
func TestExampleDNSMatchesDefaults(t *testing.T) {
	cfg, err := Load("../../configs/example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg.DNS.Upstreams, DefaultUpstreams()) {
		t.Errorf("example upstreams differ from defaults:\n%+v\n%+v", cfg.DNS.Upstreams, DefaultUpstreams())
	}
	if !reflect.DeepEqual(cfg.DNS.Sensitive, DefaultSensitive()) {
		t.Errorf("example sensitive differs from defaults")
	}
}

func TestSensitiveFallbackSetting(t *testing.T) {
	cfg, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DNS.Sensitive.FallbackFast || cfg.DNS.PolicyParams().SensitiveFallback {
		t.Error("fallback to the fast pool must be off by default")
	}
	cfg, err = Parse([]byte(minimal + "  sensitive: { fallback_fast: true }\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.DNS.PolicyParams().SensitiveFallback || len(cfg.DNS.Sensitive.Domains) != len(DefaultSensitive().Domains) {
		t.Errorf("only the switch set: %+v — want default lists kept", cfg.DNS.Sensitive)
	}
}

func TestDNSDevicesAndFallback(t *testing.T) {
	for name, tc := range map[string]struct{ yaml, want string }{
		"fallback on own address": {
			yaml: minimal + "  fallback: 192.168.1.1:53\n",
			want: "dns.fallback",
		},
		"bad device mode": {
			yaml: minimal + "  devices: [{ address: 192.168.1.20, mode: ignore }]\n",
			want: "dns.devices[0].mode",
		},
		"duplicate device": {
			yaml: minimal + "  devices: [{ address: 192.168.1.20, mode: exempt }, { address: 192.168.1.20, mode: block }]\n",
			want: "duplicate",
		},
	} {
		if _, err := Parse([]byte(tc.yaml)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
	cfg, err := Parse([]byte(minimal + "  fallback: 192.168.1.1:5353\n  devices: [{ address: 192.168.1.20, mode: exempt }]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DNS.Fallback.Port() != 5353 || len(cfg.DNS.Devices) != 1 {
		t.Errorf("dns: %+v", cfg.DNS)
	}
}

func TestListsManual(t *testing.T) {
	cfg, err := Parse([]byte(minimal + "lists:\n  manual:\n    - { domains: [example.org], purpose: bypass }\n    - { domains: [time.example], exact: true, purpose: never }\n"))
	if err != nil {
		t.Fatal(err)
	}
	rules := cfg.Lists.ManualRules()
	if len(rules) != 2 || rules[0].Match != "suffix" || rules[1].Match != "exact" || rules[0].Source != "user" {
		t.Errorf("manual rules %+v", rules)
	}
	for name, tc := range map[string]struct{ yaml, want string }{
		"class without class": {minimal + "lists:\n  manual:\n    - { domains: [a.example], purpose: class }\n", "lists.manual[0].class"},
		"bad purpose":         {minimal + "lists:\n  manual:\n    - { domains: [a.example], purpose: maybe }\n", "lists.manual[0].purpose"},
		"upper case":          {minimal + "lists:\n  manual:\n    - { domains: [A.example], purpose: never }\n", "lists.manual[0].domains"},
		"bad checksum url":    {minimal + "lists:\n  sources:\n    - { id: x, url: 'https://x/a.lst', format: text, checksum: 'ftp://x' }\n", "checksum"},
	} {
		if _, err := Parse([]byte(tc.yaml)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
