//go:build linux && integration

// Реестр устройств на стенде: настоящие сокеты (соседи ядра, DHCP через
// AF_PACKET, mDNS, SSDP, запрос имени), правило по MAC в ядре, API.
package daemon

import (
	"encoding/json"
	"io"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	coredevices "tross/core/devices"
	"tross/core/model"
	"tross/core/profile"
	"tross/internal/api"
	"tross/internal/config"
)

// apiDevice — запись из API; false — 404.
func apiDevice(t *testing.T, cfg *config.Config, id string) (api.DeviceDetail, bool) {
	t.Helper()
	resp, err := itest.do("GET", "/api/devices/"+id, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return api.DeviceDetail{}, false
	}
	var d api.DeviceDetail
	if b, _ := io.ReadAll(resp.Body); resp.StatusCode != 200 || json.Unmarshal(b, &d) != nil {
		t.Fatalf("device %s: %s %s", id, resp.Status, b)
	}
	return d, true
}

func TestDeviceRegistryOnStand(t *testing.T) {
	out, err := inNS("tl-client", "cat /sys/class/net/eth0/address")
	if err != nil {
		t.Fatal(err)
	}
	mac := strings.TrimSpace(out)
	id := "dev-" + strings.ReplaceAll(mac, ":", "")
	cfg := classCfg(t)
	r, err := coredevices.ParseRef(mac)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Classify.Rules = append(cfg.Classify.Rules, config.ClassifyRule{Name: "by-mac", Class: model.ClassBulk, Devices: []coredevices.Ref{r},
		Match: profile.Match{Proto: model.ProtoTCP, Ports: []profile.PortRange{{From: 45678, To: 45678}}}})
	set := "tross_ud" + strconv.Itoa(len(cfg.Classify.Rules)-1)

	// «Телефон» клиента отвечает на запрос имени.
	mdnsd := exec.Command("ip", "netns", "exec", "tl-client", labsrvBin(t), "mdnsd", "-name", "lab-client", "-addr", benchClient, "-duration", "90s")
	if err := mdnsd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mdnsd.Process.Kill(); _ = mdnsd.Wait() })
	// Соседа — заново: устройство должно появиться по свежему ответу ARP.
	_, _ = inNS("tl-tross", "ip neigh flush dev lan")

	stop := startDaemon(t, cfg)
	defer stop()
	start := time.Now()
	if out, err := inNS("tl-client", "ping -c2 -W1 -i0.3 192.168.77.1"); err != nil {
		t.Fatalf("ping: %v %s", err, out)
	}
	until(t, 60*time.Second, "client in the registry with its address", func() bool {
		d, ok := apiDevice(t, cfg, id)
		return ok && d.Addr.String() == benchClient
	})
	t.Logf("client in the registry after %v", time.Since(start).Round(time.Millisecond))
	until(t, 15*time.Second, "name from the mDNS query", func() bool {
		d, _ := apiDevice(t, cfg, id)
		return d.Hints.MDNSName == "lab-client"
	})
	// Правило по MAC — адрес клиента во множестве правила.
	until(t, 5*time.Second, "client address in the rule set", func() bool { return strings.Contains(nftSet(t, set), benchClient) })

	// SSDP: подсказка и тип.
	if out, err := inNS("tl-client", labsrvBin(t)+" announce -ssdp 'Linux/4.4 UPnP/1.0 webOS/1.0'"); err != nil {
		t.Fatalf("ssdp: %v %s", err, out)
	}
	until(t, 5*time.Second, "SSDP hint", func() bool {
		d, _ := apiDevice(t, cfg, id)
		return strings.Contains(d.Hints.SSDPServer, "webOS")
	})

	// DHCP: устройство только по запросу DHCP (адреса ещё нет).
	if out, err := inNS("tl-client", labsrvBin(t)+" announce -dhcp -mac a6:00:00:00:00:77 -hostname Galaxy-S23-Lab -vendor android-dhcp-14 -params 1,3,6,15,26,28,51,58,59,43"); err != nil {
		t.Fatalf("dhcp: %v %s", err, out)
	}
	until(t, 5*time.Second, "device from a DHCP request", func() bool {
		d, ok := apiDevice(t, cfg, "dev-a60000000077")
		return ok && d.Hints.DHCPHostname == "Galaxy-S23-Lab" && d.Type == model.DeviceTypePhone && d.Hints.DHCPParams != ""
	})
	// mDNS-анонс с моделью.
	if out, err := inNS("tl-client", labsrvBin(t)+" announce -mdns Owners-MacBook -addr "+benchClient+" -model MacBookPro18,3"); err != nil {
		t.Fatalf("mdns: %v %s", err, out)
	}
	until(t, 10*time.Second, "mDNS announcement", func() bool {
		d, _ := apiDevice(t, cfg, id)
		return d.Hints.MDNSModel == "MacBookPro18,3"
	})

	// Событие о новом устройстве — в журнале.
	var evs struct{ Events []struct{ Topic string } }
	getJSON(t, "http://"+cfg.API.Listen+"/api/events?limit=200", &evs)
	n := 0
	for _, e := range evs.Events {
		if e.Topic == "device.new" {
			n++
		}
	}
	if n < 2 {
		t.Errorf("device.new events: %d", n)
	}
	d, _ := apiDevice(t, cfg, id)
	if len(d.Addrs) == 0 || d.Addrs[0].IP.String() != benchClient {
		t.Errorf("address history %+v", d.Addrs)
	}
	t.Logf("client: type %s, hints %+v", d.Type, d.Hints)
}
