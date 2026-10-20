//go:build linux && integration

// Обход DPI на стенде с настоящим движком (nfqws2 в /opt/zapret2): движок
// канала запускается с сохранённой стратегией, адрес домена обхода — в
// множестве канала, соединение с обходом проходит тем же каналом, домен вне
// списка и QUIC, убитый движок (fail-open), перезапуск.
package daemon

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	coredpi "tross/core/dpi"
	"tross/core/model"
	"tross/internal/config"
	"tross/internal/store"
)

const dpiDomain = "dpi.lab.example"

func engineRunning() bool { return exec.Command("pgrep", "-x", "nfqws2").Run() == nil }

// tlsGet — HTTPS с клиента к серверу стенда с именем sni; ответ /whoami.
func tlsGet(t *testing.T, sni string) (string, error) {
	t.Helper()
	out, err := inNS("tl-client", labsrvBin(t)+" tlsget -addr "+benchSrv+":443 -sni "+sni+" -timeout 4s")
	return strings.TrimSpace(out), err
}

// ruleCounter — пакеты счётчика первого правила цепочки, содержащего what.
func ruleCounter(t *testing.T, chain, what string) int {
	t.Helper()
	out, err := exec.Command("nft", "list", "chain", "inet", "tross", chain).CombinedOutput()
	if err != nil {
		t.Fatalf("nft list chain %s: %v %s", chain, err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, what) {
			m := regexp.MustCompile(`counter packets (\d+)`).FindStringSubmatch(line)
			if m != nil {
				n, _ := strconv.Atoi(m[1])
				return n
			}
		}
	}
	t.Fatalf("%s: no rule with %q:\n%s", chain, what, out)
	return 0
}

func TestDPIEngineOnStand(t *testing.T) {
	if _, err := os.Stat("/opt/zapret2/nfqws2"); err != nil {
		t.Skip("nfqws2 is not installed in /opt/zapret2")
	}
	if engineRunning() {
		t.Fatal("an nfqws2 is already running")
	}
	cfg := classCfg(t)
	cfg.DPI.Enabled, cfg.DPI.Links = true, []model.LinkID{"isp1"}
	cfg.DPI.Dir = "/run/tross-dpi-itest"
	// Журнал движка — для разбора, если тест упадёт (остаётся в каталоге).
	cfg.DPI.Debug = true
	_ = os.RemoveAll(cfg.DPI.Dir)
	t.Cleanup(func() {
		if !t.Failed() {
			_ = os.RemoveAll(cfg.DPI.Dir)
		}
	})
	cfg.Lists.Manual = []config.ListRule{{Domains: []string{dpiDomain}, Purpose: model.PurposeBypass}}
	// Стратегия канала «уже подобрана» — из базы, как после перезапуска.
	st, err := store.Open(filepath.Join(cfg.Daemon.DataDir, dbFile), store.DefaultRetention())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveDPIScores(context.Background(), "isp1", []coredpi.Score{{Strategy: "split-1-midsld", Opened: 1, LastOK: time.Now()}}); err != nil {
		t.Fatal(err)
	}
	st.Close()

	stop := startDaemon(t, cfg)
	until(t, 10*time.Second, "engine started", engineRunning)
	if got := dig(t, "192.168.77.1", dpiDomain, ""); got != benchSrv {
		t.Fatalf("dig %s: %q", dpiDomain, got)
	}
	if s := nftSet(t, "tross_dpi0"); !strings.Contains(s, benchSrv) {
		t.Fatalf("address not in the isp1 bypass set:\n%s", s)
	}
	if b, _ := os.ReadFile(filepath.Join(cfg.DPI.Dir, "isp1.hosts")); string(b) != dpiDomain+"\n" {
		t.Errorf("hostlist %q", b)
	}

	// У «провайдера» — счётчик пакетов с данными к 443 (длиннее голого ACK):
	// движок режет ClientHello на части — у домена обхода их больше, чем у
	// того же соединения с чужим именем.
	if out, err := inNS("tl-isp1", "nft add table ip tltest && nft add chain ip tltest c '{ type filter hook forward priority 0 ; }' && nft add rule ip tltest c tcp dport 443 ip length gt 52 counter"); err != nil {
		t.Fatalf("provider counter: %v %s", err, out)
	}
	t.Cleanup(func() { _, _ = inNS("tl-isp1", "nft delete table ip tltest") })
	dataPkts := func() int {
		out, _ := inNS("tl-isp1", "nft list chain ip tltest c")
		m := regexp.MustCompile(`counter packets (\d+)`).FindStringSubmatch(out)
		if m == nil {
			t.Fatalf("provider counter:\n%s", out)
		}
		n, _ := strconv.Atoi(m[1])
		return n
	}
	p0 := dataPkts()
	if _, err := tlsGet(t, "plain.lab.example"); err != nil {
		t.Fatal(err)
	}
	plain := dataPkts() - p0

	before := ruleCounter(t, "dpi_post", "@tross_dpi0")
	p1 := dataPkts()
	// Сегменты, нарезанные движком, должны уйти тем же каналом — иначе
	// соединение не сложится.
	if got, err := tlsGet(t, dpiDomain); err != nil || !strings.HasPrefix(got, "src=100.64.1.2") {
		t.Fatalf("with bypass: %q %v, want an answer via isp1", got, err)
	}
	if after := ruleCounter(t, "dpi_post", "@tross_dpi0"); after <= before {
		t.Errorf("no packets went to the queue: %d → %d", before, after)
	}
	t.Logf("queued packets for one connection: %d", ruleCounter(t, "dpi_post", "@tross_dpi0")-before)
	split := dataPkts() - p1
	t.Logf("data packets to 443 at the provider: plain name %d, bypass name %d", plain, split)
	if split <= plain {
		t.Errorf("ClientHello not split by the engine: %d data packets, %d without bypass", split, plain)
	}
	// Чужое имя на том же адресе — движок пропускает нетронутым.
	if got, err := tlsGet(t, "other.lab.example"); err != nil || !strings.HasPrefix(got, "src=") {
		t.Errorf("name outside the hostlist: %q %v", got, err)
	}
	// QUIC к домену обхода — отказ.
	q := ruleCounter(t, "dpi_fwd", "udp dport 443")
	_, _ = inNS("tl-client", "printf quic > /dev/udp/"+benchSrv+"/443")
	time.Sleep(300 * time.Millisecond)
	if ruleCounter(t, "dpi_fwd", "udp dport 443") <= q {
		t.Error("QUIC to the bypass address was not rejected")
	}

	// Движок убит — трафик идёт мимо очереди; сторож поднимает движок.
	if out, err := exec.Command("pkill", "-KILL", "-x", "nfqws2").CombinedOutput(); err != nil {
		t.Fatalf("kill engine: %v %s", err, out)
	}
	if got, err := tlsGet(t, dpiDomain); err != nil || !strings.HasPrefix(got, "src=") {
		t.Errorf("engine dead: %q %v — want fail-open", got, err)
	}
	took := until(t, 15*time.Second, "engine restarted", engineRunning)
	t.Logf("engine back in %v", took)
	if got, err := tlsGet(t, dpiDomain); err != nil || !strings.HasPrefix(got, "src=100.64.1.2") {
		t.Errorf("after restart: %q %v", got, err)
	}

	stop()
	until(t, 5*time.Second, "engine stopped with the daemon", func() bool { return !engineRunning() })
}
