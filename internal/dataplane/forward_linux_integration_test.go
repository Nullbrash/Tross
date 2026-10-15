//go:build linux && integration

package dataplane

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"tross/core/decision"
	"tross/core/model"
	"tross/core/profile"
)

// Проброс стенда: TCP и UDP 25565 «интернета» → клиент 192.168.77.10, где
// тест запускает labsrv (HTTP и эхо UDP). Снаружи — tl-inet, адреса
// каналов tl-tross — 100.64.<n>.2.
const fwdPort = "25565"

func forwardStand(t *testing.T, guard InboundGuard) Spec {
	t.Helper()
	spec := standSpec()
	spec.Forwards = []PortForward{{
		Name: "lab", Protos: []model.Protocol{model.ProtoTCP, model.ProtoUDP},
		Ports: profile.PortRange{From: 25565, To: 25565}, To: client, Links: []model.LinkID{"isp1", "isp2"},
	}}
	spec.Guard = guard
	return spec
}

// clientServer — labsrv на клиенте стенда на время теста.
func clientServer(t *testing.T) {
	t.Helper()
	script := os.Getenv("LAB_NETNS")
	if script == "" {
		t.Fatal("LAB_NETNS not set (run via scripts/lab-itest)")
	}
	labsrv := script[:strings.LastIndex(script, "/scripts/")] + "/bin/labsrv"
	cmd := exec.Command("ip", "netns", "exec", "tl-client", labsrv, "serve",
		"-http", client.String()+":"+fwdPort, "-udp", client.String()+":"+fwdPort)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	for range 50 {
		if out, _ := inClient(t, "ss -ltn sport = :"+fwdPort); strings.Contains(out, fwdPort) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("labsrv on the client did not start")
}

// fromInternet — HTTP-запрос из «интернета» на адрес канала; true — ответ пришёл.
func fromInternet(t *testing.T, link int) bool {
	t.Helper()
	out, err := run(t, "ip", "netns", "exec", "tl-inet", "wget", "-q", "-T", "2", "--tries=1", "-O", "-",
		"http://100.64."+strconv.Itoa(link)+".2:"+fwdPort+"/")
	return err == nil && strings.TrimSpace(out) == "ok"
}

func TestPortForwardAnswersThroughArrivalLink(t *testing.T) {
	s := newSystem(t)
	spec := forwardStand(t, InboundGuard{NewPerMinute: 1000, Burst: 1000, MaxConns: 1000})
	ctx := context.Background()
	if err := s.Setup(ctx, spec); err != nil {
		t.Fatal(err)
	}
	setPlan(t, s, decision.ClassPlan{Class: model.ClassDefault, Shares: one("isp1"), PinLinks: []model.LinkID{"isp1"}})
	clientServer(t)
	// isp2 — не основной канал: без метки «откуда пришло» ответ ушёл бы
	// через isp1 с чужим адресом и потерялся.
	for _, link := range []int{1, 2} {
		if !fromInternet(t, link) {
			t.Errorf("forward through isp%d: no answer", link)
		}
	}
	// UDP — эхо labsrv через isp2.
	out, err := run(t, "ip", "netns", "exec", "tl-inet", "bash", "-c",
		"exec 3<>/dev/udp/100.64.2.2/"+fwdPort+"; printf 'ping-forward-udp' >&3; timeout 2 head -c 16 <&3")
	if err != nil || out != "ping-forward-udp" {
		t.Errorf("udp forward through isp2: %q, %v", out, err)
	}
	// LTE в пробросе нет: снаружи через него порт закрыт.
	if out, err := run(t, "ip", "netns", "exec", "tl-inet", "wget", "-q", "-T", "2", "--tries=1", "-O", "-",
		"http://100.64.3.2:"+fwdPort+"/"); err == nil {
		t.Errorf("forward answered through lte: %q", out)
	}

	conns, err := s.Connections(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var throughISP2 bool
	var inbound []Connection
	for _, c := range conns {
		if c.Forward.IsValid() {
			inbound = append(inbound, c)
			throughISP2 = throughISP2 || c.Forward == netip.AddrPortFrom(client, 25565) && c.Link == "isp2" && c.Dst.Addr() == netip.MustParseAddr("100.64.2.2")
		}
	}
	if !throughISP2 {
		t.Errorf("no inbound connection via isp2 with forward target in conntrack; inbound: %+v", inbound)
	}
}

// Остановка демона снимает разметку, но не проброс и не защиту (D-44):
// через основной канал сервер доступен и без демона.
func TestPortForwardSurvivesTeardown(t *testing.T) {
	s := newSystem(t)
	spec := forwardStand(t, InboundGuard{NewPerMinute: 1000, Burst: 1000, MaxConns: 1000})
	ctx := context.Background()
	if err := s.Setup(ctx, spec); err != nil {
		t.Fatal(err)
	}
	setPlan(t, s, decision.ClassPlan{Class: model.ClassDefault, Shares: one("isp1"), PinLinks: []model.LinkID{"isp1"}})
	clientServer(t)
	// Без демона ответы идут по основной таблице: на мини-ПК там маршрут
	// основного канала (DHCP), на стенде его нет — ставится на время теста.
	if out, _ := run(t, "ip", "route", "show", "default"); strings.TrimSpace(out) == "" {
		if out, err := run(t, "ip", "route", "add", "default", "via", "100.64.1.1", "dev", "wan1"); err != nil {
			t.Fatalf("main default route: %v %s", err, out)
		}
		t.Cleanup(func() { _, _ = run(t, "ip", "route", "del", "default", "via", "100.64.1.1", "dev", "wan1") })
	}
	if err := s.Teardown(ctx); err != nil {
		t.Fatal(err)
	}
	if !fromInternet(t, 1) {
		t.Error("forward through the main link stopped with the daemon")
	}
	nat, _ := run(t, "nft", "list", "table", "inet", nftNATTable)
	if !strings.Contains(nat, "dnat ip to") || !strings.Contains(nat, setInConn) {
		t.Errorf("forward or guard gone after teardown:\n%s", nat)
	}
}

func TestInboundGuardLimitsRate(t *testing.T) {
	s := newSystem(t)
	spec := forwardStand(t, InboundGuard{NewPerMinute: 1, Burst: 3, MaxConns: 1000})
	if err := s.Setup(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	setPlan(t, s, decision.ClassPlan{Class: model.ClassDefault, Shares: one("isp1"), PinLinks: []model.LinkID{"isp1"}})
	clientServer(t)
	ok := 0
	for range 8 {
		if fromInternet(t, 1) {
			ok++
		}
	}
	// Всплеск 3 (+1 по скорости) проходит, остальное отбрасывается.
	if ok < 2 || ok > 5 {
		t.Errorf("%d of 8 rapid connections passed, want burst ~3", ok)
	}
	t.Logf("measure: rate guard let %d of 8 rapid connections through (burst 3, 1/min)", ok)
}

func TestInboundGuardLimitsConcurrent(t *testing.T) {
	s := newSystem(t)
	spec := forwardStand(t, InboundGuard{NewPerMinute: 1000, Burst: 1000, MaxConns: 2})
	if err := s.Setup(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	setPlan(t, s, decision.ClassPlan{Class: model.ClassDefault, Shares: one("isp1"), PinLinks: []model.LinkID{"isp1"}})
	clientServer(t)
	// Два соединения держатся открытыми, третье с того же адреса не проходит.
	hold := exec.Command("ip", "netns", "exec", "tl-inet", "bash", "-c",
		"exec 3<>/dev/tcp/100.64.1.2/"+fwdPort+"; exec 4<>/dev/tcp/100.64.1.2/"+fwdPort+"; sleep 6")
	if err := hold.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hold.Process.Kill(); _ = hold.Wait() })
	time.Sleep(time.Second)
	if fromInternet(t, 1) {
		t.Error("third concurrent connection passed with max_connections 2")
	}
	_ = hold.Process.Kill()
	_ = hold.Wait()
	// После закрытия — снова можно (счётчик conntrack освобождается не сразу).
	deadline := time.Now().Add(15 * time.Second)
	for !fromInternet(t, 1) {
		if time.Now().After(deadline) {
			t.Fatal("connections still refused after the held ones closed")
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// Провайдер стенда направляет к нам пакеты на адреса LAN (на настоящем
// канале этого не бывает только потому, что провайдер так не делает):
// без Tross они доходят до устройства, с Tross — нет, и после остановки
// демона — тоже нет; исходящие соединения дома при этом работают.
func TestInboundFilterBlocksUnsolicited(t *testing.T) {
	s := newSystem(t)
	clientServer(t)
	ns := func(name string, args ...string) {
		t.Helper()
		if out, err := run(t, "ip", append([]string{"netns", "exec", name, "ip", "route"}, args...)...); err != nil {
			t.Fatalf("%s: ip route %v: %v %s", name, args, err, out)
		}
	}
	ns("tl-isp1", "add", "192.168.77.0/24", "via", "100.64.1.2")
	t.Cleanup(func() { _, _ = run(t, "ip", "netns", "exec", "tl-isp1", "ip", "route", "del", "192.168.77.0/24") })
	ns("tl-inet", "add", "192.168.77.0/24", "via", "198.18.1.1")
	t.Cleanup(func() { _, _ = run(t, "ip", "netns", "exec", "tl-inet", "ip", "route", "del", "192.168.77.0/24") })
	if out, _ := run(t, "ip", "route", "show", "default"); strings.TrimSpace(out) == "" {
		if out, err := run(t, "ip", "route", "add", "default", "via", "100.64.1.1", "dev", "wan1"); err != nil {
			t.Fatalf("main default route: %v %s", err, out)
		}
		t.Cleanup(func() { _, _ = run(t, "ip", "route", "del", "default", "via", "100.64.1.1", "dev", "wan1") })
	}
	direct := func() bool {
		out, err := run(t, "ip", "netns", "exec", "tl-inet", "wget", "-q", "-T", "2", "--tries=1", "-O", "-",
			"http://"+client.String()+":"+fwdPort+"/")
		return err == nil && strings.TrimSpace(out) == "ok"
	}
	if !direct() {
		t.Fatal("without Tross the device must be reachable on the bench — the check would prove nothing")
	}

	ctx := context.Background()
	if err := s.Setup(ctx, standSpec()); err != nil {
		t.Fatal(err)
	}
	setPlan(t, s, decision.ClassPlan{Class: model.ClassDefault, Shares: one("isp1"), PinLinks: []model.LinkID{"isp1"}})
	if direct() {
		t.Error("unsolicited inbound reached the device through Tross")
	}
	if got, err := fetch(t, 100_000); err != nil || got != 100_000 {
		t.Errorf("outbound from LAN with the filter: %d, %v", got, err)
	}
	if err := s.Teardown(ctx); err != nil {
		t.Fatal(err)
	}
	if direct() {
		t.Error("unsolicited inbound reached the device after the daemon stopped")
	}
	nat, _ := run(t, "nft", "list", "chain", "inet", nftNATTable, "forward")
	t.Logf("measure: inbound filter after teardown:\n%s", nat)
}
