//go:build linux && integration

// «Глазами чужого»: что видно со стороны провайдера. Провайдер стенда
// (tl-isp1) стучится на внешний адрес Tross и — как злонамеренный —
// направляет пакеты прямо на адреса LAN через Tross. Открыто должно быть
// только проброшенное (ручной проброс и проброс по UPnP).
package daemon

import (
	"os/exec"
	"strings"
	"testing"
	"time"
)

// tcpState — open (соединение), refused (RST) или silent (ответа нет).
func tcpState(t *testing.T, ns, addr, port string) string {
	t.Helper()
	start := time.Now()
	_, err := inNS(ns, "timeout 2 bash -c '</dev/tcp/"+addr+"/"+port+"'")
	switch {
	case err == nil:
		return "open"
	case time.Since(start) < 1500*time.Millisecond:
		return "refused"
	}
	return "silent"
}

func TestOutsiderSeesOnlyForwards(t *testing.T) {
	cfg := classCfg(t)
	cfg.UPnP.Enabled = true
	out, err := inNS("tl-client", "cat /sys/class/net/eth0/address")
	if err != nil {
		t.Fatal(err)
	}
	id := "dev-" + strings.ReplaceAll(strings.TrimSpace(out), ":", "")
	_, _ = inNS("tl-tross", "nft delete table inet tross_upnp")
	t.Cleanup(func() { _, _ = inNS("tl-tross", "nft delete table inet tross_upnp") })
	startDaemon(t, cfg)
	if _, err := inNS("tl-client", "ping -c2 -W1 -i0.3 192.168.77.1"); err != nil {
		t.Fatal(err)
	}
	until(t, 30*time.Second, "client in the registry", func() bool { _, ok := apiDevice(t, cfg, id); return ok })
	patchDevice(t, "http://"+cfg.API.Listen+"/api/devices/"+id, `{"upnp":"allow"}`)
	if got := upnpc(t, "-igd -proto tcp -port 45000 -lease 600 -desc server"); got != "ok" {
		t.Fatalf("upnp mapping: %q", got)
	}
	srv := exec.Command("ip", "netns", "exec", "tl-client", labsrvBin(t), "serve", "-http", benchClient+":45000", "-udp", benchClient+":46000")
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Process.Kill(); _ = srv.Wait() })
	srv2 := exec.Command("ip", "netns", "exec", "tl-client", labsrvBin(t), "serve", "-http", benchClient+":25565", "-udp", benchClient+":45001")
	if err := srv2.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv2.Process.Kill(); _ = srv2.Wait() })
	until(t, 5*time.Second, "servers on the client", func() bool {
		out, _ := inNS("tl-client", "ss -ltn")
		return strings.Contains(out, ":45000") && strings.Contains(out, ":25565")
	})

	// Злонамеренный провайдер: адреса LAN — через Tross.
	if out, err := inNS("tl-isp1", "ip route replace 192.168.77.0/24 via 100.64.1.2"); err != nil {
		t.Fatalf("route: %v %s", err, out)
	}
	t.Cleanup(func() { _, _ = inNS("tl-isp1", "ip route del 192.168.77.0/24 via 100.64.1.2") })

	wan, lan, client := "100.64.1.2", "192.168.77.1", benchClient
	// Проброшенное — открыто.
	for _, p := range []string{"25565", "45000"} {
		if s := tcpState(t, "tl-isp1", wan, p); s != "open" {
			t.Errorf("forwarded %s:%s from the provider: %s", wan, p, s)
		}
	}
	// Остальное: службы мини-ПК (SSH, DNS, API, IGD, запасной DNS) по
	// внешнему адресу и по адресу LAN, порты клиента напрямую, непроброшенный
	// порт.
	report := map[string]string{}
	for _, c := range []struct{ addr, port string }{
		{wan, "22"}, {wan, "53"}, {wan, "8080"}, {wan, "5000"}, {wan, "5335"}, {wan, "45001"},
		{lan, "22"}, {lan, "53"}, {lan, "8080"}, {lan, "5000"}, {lan, "5335"},
		{client, "45000"}, {client, "25565"},
	} {
		// Не только закрыто — молчит: отказ выдал бы, что машина есть.
		s := tcpState(t, "tl-isp1", c.addr, c.port)
		report[c.addr+":"+c.port] = s
		if s != "silent" {
			t.Errorf("from the provider: tcp %s:%s is %s, want silent", c.addr, c.port, s)
		}
	}
	t.Logf("measure: tcp from the provider: %v", report)
	// UDP: DNS и NAT-PMP мини-ПК с обоих адресов — без ответа.
	for _, a := range []string{wan, lan} {
		if out, err := inNS("tl-isp1", "dig +short +time=2 +tries=1 @"+a+" example.org"); err == nil && strings.TrimSpace(out) != "" {
			t.Errorf("DNS answers the provider at %s: %q", a, out)
		}
		if out, _ := inNS("tl-isp1", labsrvBin(t)+" upnpc -natpmp -gw "+a+" -proto tcp -port 50000 -lease 60"); strings.HasPrefix(strings.TrimSpace(out), "ok") || strings.HasPrefix(strings.TrimSpace(out), "result") {
			t.Errorf("NAT-PMP answers the provider at %s: %q", a, out)
		}
	}
	// SSDP поиск напрямую на адрес LAN — без ответа (и IGD по HTTP закрыт выше).
	if out, _ := inNS("tl-isp1", "printf 'M-SEARCH * HTTP/1.1\\r\\nHOST: 239.255.255.250:1900\\r\\nMAN: \"ssdp:discover\"\\r\\nMX: 1\\r\\nST: ssdp:all\\r\\n\\r\\n' | timeout 3 nc -u -w 2 "+lan+" 1900 2>/dev/null || true"); strings.Contains(out, "LOCATION") {
		t.Errorf("SSDP answers the provider: %q", out)
	}
	// Изнутри — всё по-прежнему доступно.
	if s := tcpState(t, "tl-client", lan, "8080"); s != "open" {
		t.Errorf("API from LAN: %s", s)
	}
}
