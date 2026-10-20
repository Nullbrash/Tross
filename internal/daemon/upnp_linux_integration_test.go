//go:build linux && integration

// Пробросы по запросу программ на стенде: UPnP IGD (поиск SSDP, SOAP),
// NAT-PMP и PCP с клиента; уровни доверия; входящие из «интернета» через оба
// проводных канала, не через LTE; пробросы переживают остановку демона.
package daemon

import (
	"bytes"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"

	"tross/internal/api"
)

func upnpc(t *testing.T, args string) string {
	t.Helper()
	out, err := inNS("tl-client", labsrvBin(t)+" upnpc "+args)
	if err != nil {
		ss, _ := inNS("tl-tross", "ss -lunpt")
		t.Fatalf("upnpc %s: %v %s\nsockets in tl-tross:\n%s", args, err, out, ss)
	}
	return strings.TrimSpace(out)
}

func patchDevice(t *testing.T, url, body string) {
	t.Helper()
	req, _ := http.NewRequest("PATCH", url, bytes.NewBufferString(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("patch %s: %v %v", body, resp, err)
	}
	resp.Body.Close()
}

func TestUPnPOnStand(t *testing.T) {
	cfg := classCfg(t)
	cfg.UPnP.Enabled = true
	out, err := inNS("tl-client", "cat /sys/class/net/eth0/address")
	if err != nil {
		t.Fatal(err)
	}
	id := "dev-" + strings.ReplaceAll(strings.TrimSpace(out), ":", "")
	_, _ = inNS("tl-tross", "nft delete table inet tross_upnp")
	t.Cleanup(func() { _, _ = inNS("tl-tross", "nft delete table inet tross_upnp") })
	stop := startDaemon(t, cfg)
	defer stop()
	if _, err := inNS("tl-client", "ping -c2 -W1 -i0.3 192.168.77.1"); err != nil {
		t.Fatal(err)
	}
	until(t, 30*time.Second, "client in the registry", func() bool { _, ok := apiDevice(t, cfg, id); return ok })
	devURL := "http://" + cfg.API.Listen + "/api/devices/" + id

	// Новое устройство (тип угадан) — права нет.
	if got := upnpc(t, "-igd -proto tcp -port 45000 -lease 0 -desc TorrentClient"); got != "error 606" {
		t.Fatalf("untrusted device: %q", got)
	}
	patchDevice(t, devURL, `{"upnp":"allow"}`)
	if got := upnpc(t, "-igd -proto tcp -port 45000 -lease 0 -desc TorrentClient"); got != "ok" {
		t.Fatalf("igd: %q", got)
	}
	srv := exec.Command("ip", "netns", "exec", "tl-client", labsrvBin(t), "serve", "-http", benchClient+":45000", "-udp", benchClient+":46000")
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Process.Kill(); _ = srv.Wait() })
	until(t, 5*time.Second, "server on the client", func() bool {
		out, _ := inNS("tl-client", "ss -ltn sport = :45000")
		return strings.Contains(out, "45000")
	})
	// Входящие — через оба проводных канала; через LTE — нет.
	for _, wan := range []string{"100.64.1.2", "100.64.2.2"} {
		if out, err := inNS("tl-inet", "wget -q -T 3 --tries=1 -O - http://"+wan+":45000/"); err != nil || strings.TrimSpace(out) != "ok" {
			t.Errorf("mapping via %s: %q %v", wan, out, err)
		}
	}
	if out, err := inNS("tl-inet", "wget -q -T 2 --tries=1 -O - http://100.64.3.2:45000/"); err == nil {
		t.Errorf("mapping must not be open via LTE: %q", out)
	}
	// NAT-PMP и PCP.
	if got := upnpc(t, "-natpmp -gw 192.168.77.1 -proto udp -port 46000 -lease 7200"); got != "ok 46000 3600" {
		t.Errorf("nat-pmp: %q", got)
	}
	if got := upnpc(t, "-pcp -gw 192.168.77.1 -proto tcp -port 47000 -lease 600"); got != "ok 47000 600" {
		t.Errorf("pcp: %q", got)
	}
	// Порт ниже 1024 — отказ.
	if got := upnpc(t, "-natpmp -gw 192.168.77.1 -proto tcp -port 80 -lease 60"); got != "result 2" {
		t.Errorf("low port: %q", got)
	}
	var st api.UPnPStatus
	getJSON(t, "http://"+cfg.API.Listen+"/api/upnp", &st)
	if len(st.Mappings) != 3 || st.Mappings[0].Device != id {
		t.Fatalf("status %+v", st)
	}
	// Снять своё по IGD.
	if got := upnpc(t, "-igd -proto tcp -port 47000 -delete"); got != "ok" {
		t.Errorf("igd delete: %q", got)
	}

	// «Спрашивать»: отказ, запрос ждёт, «разрешить один раз» — открыт.
	patchDevice(t, devURL, `{"upnp":"ask"}`)
	if got := upnpc(t, "-igd -proto tcp -port 48000 -lease 600 -desc Game"); got != "error 606" {
		t.Fatalf("ask: %q", got)
	}
	getJSON(t, "http://"+cfg.API.Listen+"/api/upnp", &st)
	if len(st.Pending) != 1 || st.Pending[0].Desc != "Game" {
		t.Fatalf("pending %+v", st.Pending)
	}
	resp, err := http.Post("http://"+cfg.API.Listen+"/api/upnp/pending/"+st.Pending[0].ID, "application/json", bytes.NewBufferString(`{"decision":"once"}`))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("resolve: %v %v", resp, err)
	}
	resp.Body.Close()
	until(t, 5*time.Second, "mapping after approval", func() bool {
		out, _ := inNS("tl-tross", "nft list map inet tross_upnp portmap")
		return strings.Contains(out, "tcp . 48000")
	})

	// Демон остановлен — пробросы остаются в ядре (сроки держит ядро) и
	// работают через основной канал (маршрут по умолчанию системы), как
	// ручные пробросы.
	withMainDefault(t)
	stop()
	if out, err := inNS("tl-tross", "nft list map inet tross_upnp portmap"); err != nil || !strings.Contains(out, "tcp . 45000") || !strings.Contains(out, "udp . 46000") {
		t.Errorf("mappings after stop: %v\n%s", err, out)
	}
	if out, err := inNS("tl-inet", "wget -q -T 3 --tries=1 -O - http://100.64.1.2:45000/"); err != nil || strings.TrimSpace(out) != "ok" {
		t.Errorf("mapping without the daemon: %q %v", out, err)
	}
}

// Срок проброса держит ядро: демон остановлен — проброс истекает сам.
func TestUPnPExpiresWithoutDaemon(t *testing.T) {
	cfg := classCfg(t)
	cfg.UPnP.Enabled = true
	out, err := inNS("tl-client", "cat /sys/class/net/eth0/address")
	if err != nil {
		t.Fatal(err)
	}
	id := "dev-" + strings.ReplaceAll(strings.TrimSpace(out), ":", "")
	_, _ = inNS("tl-tross", "nft delete table inet tross_upnp")
	t.Cleanup(func() { _, _ = inNS("tl-tross", "nft delete table inet tross_upnp") })
	stop := startDaemon(t, cfg)
	defer stop()
	if _, err := inNS("tl-client", "ping -c2 -W1 -i0.3 192.168.77.1"); err != nil {
		t.Fatal(err)
	}
	until(t, 30*time.Second, "client in the registry", func() bool { _, ok := apiDevice(t, cfg, id); return ok })
	patchDevice(t, "http://"+cfg.API.Listen+"/api/devices/"+id, `{"upnp":"allow"}`)
	if got := upnpc(t, "-natpmp -gw 192.168.77.1 -proto udp -port 46500 -lease 15"); got != "ok 46500 15" {
		t.Fatalf("nat-pmp: %q", got)
	}
	stop()
	has := func() bool {
		out, _ := inNS("tl-tross", "nft list map inet tross_upnp portmap")
		return strings.Contains(out, "udp . 46500")
	}
	if !has() {
		t.Fatal("mapping gone right after stop")
	}
	took := until(t, 30*time.Second, "mapping expired without the daemon", func() bool { return !has() })
	t.Logf("measure: 15 s mapping expired %v after the daemon stopped", took.Round(time.Second))
}
