package config

import (
	"strings"
	"testing"
	"time"
)

func dhcpYAML(dhcp string) string {
	return strings.Replace(minimal, "  networks: [192.168.1.0/24]\n", "  networks: [192.168.1.0/24]\n  dhcp: "+dhcp+"\n", 1)
}

func TestDHCPSection(t *testing.T) {
	cfg, err := Parse([]byte(dhcpYAML("{ enabled: true }")))
	if err != nil {
		t.Fatal(err)
	}
	d := cfg.LAN.DHCP
	// Умолчания: диапазон .100–.249 сети /24, шлюз — адрес резолвера,
	// свой каталог вне data_dir.
	if d.Range != "192.168.1.100-192.168.1.249" || d.Gateway.String() != "192.168.1.1" || d.Lease != 12*time.Hour ||
		d.Dir != "/var/lib/tross-dhcp" || d.Unit != "tross-dhcp.service" {
		t.Fatalf("defaults %+v", d)
	}
	if _, err := Parse([]byte(dhcpYAML("{ enabled: true, range: 192.168.1.50-192.168.1.60, lease: 1h, unit: none }"))); err != nil {
		t.Errorf("explicit range: %v", err)
	}
	bad := map[string]string{
		"reversed range":    "{ enabled: true, range: 192.168.1.60-192.168.1.50 }",
		"range outside LAN": "{ enabled: true, range: 10.0.0.10-10.0.0.20 }",
		"no dash":           "{ enabled: true, range: 192.168.1.50 }",
		"network address":   "{ enabled: true, range: 192.168.1.0-192.168.1.20 }",
		"gateway in range":  "{ enabled: true, range: 192.168.1.1-192.168.1.20 }",
		"gateway off LAN":   "{ enabled: true, gateway: 10.0.0.1 }",
		"short lease":       "{ enabled: true, lease: 30s }",
		"relative dir":      "{ enabled: true, dir: dhcp }",
	}
	for name, y := range bad {
		if _, err := Parse([]byte(dhcpYAML(y))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Выключенная раздача не проверяется.
	if _, err := Parse([]byte(dhcpYAML("{ enabled: false, range: junk }"))); err != nil {
		t.Errorf("disabled: %v", err)
	}
}
