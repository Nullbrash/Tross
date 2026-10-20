package config

import (
	"testing"
	"time"
)

func TestUPnPSection(t *testing.T) {
	cfg, err := Parse([]byte(minimal + "upnp: { enabled: true }\n"))
	if err != nil {
		t.Fatal(err)
	}
	u := cfg.UPnP
	if u.HTTPPort != 5000 || u.MaxLease != time.Hour || u.MaxPerDevice != 16 {
		t.Fatalf("defaults %+v", u)
	}
	// По умолчанию — только проводные каналы: LTE не открывается.
	if ls := cfg.UPnPLinks(); len(ls) != 1 || ls[0].ID != "isp1" {
		t.Errorf("links %+v", ls)
	}
	if cfg, err := Parse([]byte(minimal + "upnp: { enabled: true, links: [lte, isp1] }\n")); err != nil || len(cfg.UPnPLinks()) != 2 {
		t.Errorf("explicit links: %v", err)
	}
	bad := map[string]string{
		"unknown link": "upnp: { enabled: true, links: [isp9] }\n",
		"short lease":  "upnp: { enabled: true, max_lease: 30s }\n",
		"port clash":   "upnp: { enabled: true, http_port: 5351 }\n",
		"zero limit":   "upnp: { enabled: true, max_per_device: -1 }\n",
	}
	for name, y := range bad {
		if _, err := Parse([]byte(minimal + y)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	noLAN := "lan: { interface: br0, networks: [192.168.1.0/24] }\nlinks: [{ id: isp1, kind: wired, interface: eth1 }]\nupnp: { enabled: true }\n"
	if _, err := Parse([]byte(noLAN)); err == nil {
		t.Error("no LAN address accepted")
	}
}
