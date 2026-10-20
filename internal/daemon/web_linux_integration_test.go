//go:build linux && integration

// Интерфейс с клиента стенда: корневой сертификат по HTTP, HTTPS с его
// проверкой, имя интерфейса от резолвера Tross, без входа — закрыто.
package daemon

import (
	"strings"
	"testing"
)

func TestWebFromClient(t *testing.T) {
	cfg := classCfg(t)
	cfg.API.HTTPListen = "192.168.77.1:8081"
	startDaemon(t, cfg)
	ca := "/tmp/tross-itest-ca.crt"
	t.Cleanup(func() { _, _ = inNS("tl-client", "rm -f "+ca) })
	if out, err := inNS("tl-client", "wget -q -T 3 -O "+ca+" http://192.168.77.1:8081/ca.crt"); err != nil {
		t.Fatalf("ca over http: %v %s", err, out)
	}
	// HTTPS проверяется скачанным корневым (адрес — в сертификате).
	if out, err := inNS("tl-client", "wget -q -T 3 -O - --ca-certificate="+ca+" https://192.168.77.1:8080/api/health"); err != nil || !strings.Contains(out, `"status":"ok"`) {
		t.Fatalf("https with the root: %v %s", err, out)
	}
	// Без корневого — браузер (и wget) не доверяет.
	if _, err := inNS("tl-client", "wget -q -T 3 -O - https://192.168.77.1:8080/api/health"); err == nil {
		t.Error("untrusted certificate accepted without the root")
	}
	// Без входа — закрыто.
	if out, _ := inNS("tl-client", "wget -S -q -T 3 -O /dev/null --ca-certificate="+ca+" https://192.168.77.1:8080/api/devices 2>&1"); !strings.Contains(out, "401") {
		t.Errorf("devices without login: %s", out)
	}
	// HTTP — перенаправление на HTTPS.
	if out, _ := inNS("tl-client", "wget -S -q -T 3 --max-redirect=0 -O /dev/null http://192.168.77.1:8081/devices 2>&1"); !strings.Contains(out, "Location: https://192.168.77.1:8080/devices") {
		t.Errorf("redirect: %s", out)
	}
	// Имя интерфейса — от резолвера Tross.
	if got := dig(t, "192.168.77.1", "tross.lan", ""); got != "192.168.77.1" {
		t.Errorf("tross.lan: %q", got)
	}
}
