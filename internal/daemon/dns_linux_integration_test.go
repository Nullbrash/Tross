//go:build linux && integration

// Резолвер Этапа 4 на стенде: демон целиком, клиент — tl-client, «интернет»
// — DoH labsrv и dnsmasq стенда (оба отвечают адресом сервера стенда на
// любое имя).
package daemon

import (
	"net/netip"
	"os/exec"
	"strings"
	"testing"
	"time"

	coredevices "tross/core/devices"
	"tross/core/model"
	"tross/internal/config"
	"tross/internal/control"
	"tross/internal/store"
)

// dig — короткий ответ с клиента (и с адреса источника src, если задан).
func dig(t *testing.T, server, name, src string) string {
	t.Helper()
	args := "dig +short +time=2 +tries=1 @" + server + " " + name
	if src != "" {
		args += " -b " + src
	}
	out, _ := inNS("tl-client", args)
	return strings.TrimSpace(out)
}

func nftSet(t *testing.T, set string) string {
	t.Helper()
	out, err := exec.Command("nft", "list", "set", "inet", "tross", set).CombinedOutput()
	if err != nil {
		t.Fatalf("nft list set %s: %v\n%s", set, err, out)
	}
	return string(out)
}

// Адрес домена профиля — в множестве ядра, когда клиент получил ответ; у
// видео (два канала) — и в множестве «домен → канал»; у прочего (порядок
// каналов — одна доля) выбирать нечего.
func TestDNSFillsSetsBeforeAnswer(t *testing.T) {
	cfg := classCfg(t)
	startDaemon(t, cfg)
	until(t, 5*time.Second, "resolver answers", func() bool { return dig(t, "192.168.77.1", "store.steampowered.com", "") == benchSrv })
	// Ответ уже у клиента — значит, адрес в множестве (ответ — только после ядра).
	if s := nftSet(t, "tross_dp_steam_store_0"); !strings.Contains(s, benchSrv) {
		t.Errorf("steam store set lacks %s after the answer:\n%s", benchSrv, s)
	}
	for _, set := range []string{"tross_dl0", "tross_dl1", "tross_dl2"} {
		if strings.Contains(nftSet(t, set), benchSrv) {
			t.Errorf("one share, yet %s got the address", set)
		}
	}
	if got := dig(t, "192.168.77.1", "www.youtube.com", ""); got != benchSrv {
		t.Fatalf("youtube: %q", got)
	}
	if s := nftSet(t, "tross_dp_youtube_video_0"); !strings.Contains(s, benchSrv) {
		t.Errorf("youtube set lacks the address:\n%s", s)
	}
	inDL := false
	for _, set := range []string{"tross_dl0", "tross_dl1", "tross_dl2"} {
		inDL = inDL || strings.Contains(nftSet(t, set), benchSrv)
	}
	if !inDL {
		t.Error("no domain-link set got the address")
	}
	// Локальные имена наружу не уходят.
	if got := dig(t, "192.168.77.1", "printer", ""); got != "" {
		t.Errorf("single-label name answered %q, want NXDOMAIN", got)
	}
}

// Обычный DNS на чужой сервер — к резолверу (однословное имя у него —
// NXDOMAIN, а dnsmasq стенда ответил бы адресом); исключённое устройство —
// мимо. Без демона всё, что дом спрашивает у мини-ПК, — запасному.
func TestDNSRedirectAndFallback(t *testing.T) {
	cfg := classCfg(t)
	second := netip.MustParseAddr("192.168.77.11")
	cfg.DNS.Devices = append(cfg.DNS.Devices, config.DNSDevice{Address: coredevices.Ref{Addr: second}, Mode: model.DNSExempt})
	if out, err := inNS("tl-client", "ip addr add "+second.String()+"/24 dev eth0"); err != nil {
		t.Fatalf("second device address: %v %s", err, out)
	}
	t.Cleanup(func() { _, _ = inNS("tl-client", "ip addr del "+second.String()+"/24 dev eth0") })
	stop := startDaemon(t, cfg)
	until(t, 5*time.Second, "redirected to the resolver", func() bool {
		return dig(t, "203.0.113.53", "printer", "") == ""
	})
	if got := dig(t, "203.0.113.53", "printer", second.String()); got != benchSrv {
		t.Errorf("exempt device redirected: %q, want the stand dns answer", got)
	}
	stop()
	if got := dig(t, "192.168.77.1", "printer", ""); got != benchSrv {
		t.Errorf("daemon stopped: mini-pc dns answered %q, want the fallback resolver (%s)", got, benchSrv)
	}
	if got := dig(t, "203.0.113.53", "printer", ""); got != benchSrv {
		t.Errorf("daemon stopped: redirected query answered %q, want the fallback", got)
	}
}

// Фаза 4: свои имена, отладочный журнал через сокет root, /api/dns.
func TestDNSHostsDebugAndAPI(t *testing.T) {
	cfg := classCfg(t)
	cfg.DNS.Hosts = map[string]netip.Addr{"nas.home.example": netip.MustParseAddr("192.168.77.50")}
	cfg.Daemon.Control = t.TempDir() + "/trossd.sock"
	startDaemon(t, cfg)
	until(t, 5*time.Second, "own name answered", func() bool { return dig(t, "192.168.77.1", "nas.home.example", "") == "192.168.77.50" })

	// Без прогона — в журнале пусто.
	var rows []store.DNSDebugRow
	if err := control.Call(cfg.Daemon.Control, control.Request{Cmd: "dns-log-export"}, &rows); err != nil || len(rows) != 0 {
		t.Fatalf("before the run: %d rows, %v", len(rows), err)
	}
	if err := control.Call(cfg.Daemon.Control, control.Request{Cmd: "dns-log-start", For: time.Minute}, nil); err != nil {
		t.Fatal(err)
	}
	if got := dig(t, "192.168.77.1", "store.steampowered.com", ""); got != benchSrv {
		t.Fatalf("dig: %q", got)
	}
	until(t, 5*time.Second, "debug rows written", func() bool {
		rows = nil
		_ = control.Call(cfg.Daemon.Control, control.Request{Cmd: "dns-log-export", Anonymize: true}, &rows)
		return len(rows) > 0
	})
	if rows[0].Name != "store.steampowered.com" || rows[0].Device != "device-1" {
		t.Errorf("row %+v", rows[0])
	}
	out, err := apiBytes("GET", "/api/dns", nil)
	if err != nil || !strings.Contains(string(out), `"serving":"resolver"`) || !strings.Contains(string(out), `"active":true`) {
		t.Errorf("/api/dns: %v %s", err, out)
	}
	_ = control.Call(cfg.Daemon.Control, control.Request{Cmd: "dns-log-purge"}, nil)
}
