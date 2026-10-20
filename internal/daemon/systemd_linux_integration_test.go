//go:build linux && integration

// Служба systemd (deploy/systemd/trossd.service) на стенде: демон в netns
// tl-tross через NetworkNamespacePath, остальное — как на мини-ПК. Проверка
// fail-open при остановке, перезапуска после kill -9 и сторожа WatchdogSec.
package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const itestUnit = "trossd-itest"

func repoRoot(t *testing.T) string {
	t.Helper()
	for _, dir := range []string{".", "../.."} {
		if _, err := os.Stat(filepath.Join(dir, "deploy/systemd/trossd.service")); err == nil {
			abs, _ := filepath.Abs(dir)
			return abs
		}
	}
	t.Fatal("repository root not found")
	return ""
}

func systemctl(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("systemctl %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func unitProp(t *testing.T, prop string) string {
	t.Helper()
	return systemctl(t, "show", "-p", prop, "--value", itestUnit)
}

// installUnit ставит службу из deploy/ с поправками стенда во временный
// каталог /run/systemd/system (исчезает при перезагрузке).
func installUnit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("systemctl"); err != nil {
		t.Skip("no systemd")
	}
	root := repoRoot(t)
	// Служба — root без обхода прав на файлы (как на мини-ПК), а домашний
	// каталог закрыт: бинарник и конфиг кладутся рядом, как /usr/local/bin и /etc/tross.
	// /run смонтирован с noexec — копия на корневой ФС.
	stage := "/usr/local/lib/tross-itest"
	if err := os.MkdirAll(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	bin, cfg := filepath.Join(stage, "trossd"), filepath.Join(stage, "lab.yaml")
	for src, dst := range map[string]string{filepath.Join(root, "bin/trossd"): bin, filepath.Join(root, "configs/lab.yaml"): cfg} {
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("%v (scripts/lab-sync itest builds bin/)", err)
		}
		if err := os.WriteFile(dst, b, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	unit, err := os.ReadFile(filepath.Join(root, "deploy/systemd/trossd.service"))
	if err != nil {
		t.Fatal(err)
	}
	dir := "/run/systemd/system"
	if err := os.WriteFile(filepath.Join(dir, itestUnit+".service"), unit, 0o644); err != nil {
		t.Fatal(err)
	}
	dropDir := filepath.Join(dir, itestUnit+".service.d")
	if err := os.MkdirAll(dropDir, 0o755); err != nil {
		t.Fatal(err)
	}
	drop := fmt.Sprintf(`[Unit]
StartLimitBurst=100

[Service]
NetworkNamespacePath=/run/netns/tl-tross
ExecStart=
ExecStart=%[1]s -config %[2]s -data-dir /var/lib/tross-itest
ExecStopPost=
ExecStopPost=%[1]s -config %[2]s -cleanup
ExecStartPre=
StateDirectory=tross-itest
ReadWritePaths=
ReadWritePaths=/var/lib/tross-itest
WatchdogSec=6
`, bin, cfg)
	if err := os.WriteFile(filepath.Join(dropDir, "lab.conf"), []byte(drop), 0o644); err != nil {
		t.Fatal(err)
	}
	systemctl(t, "daemon-reload")
	t.Cleanup(func() {
		_ = exec.Command("systemctl", "stop", itestUnit).Run()
		_ = exec.Command("systemctl", "reset-failed", itestUnit).Run()
		os.RemoveAll(dropDir)
		os.Remove(filepath.Join(dir, itestUnit+".service"))
		_ = exec.Command("systemctl", "daemon-reload").Run()
		_ = exec.Command(bin, "-config", cfg, "-purge").Run()
		os.RemoveAll("/var/lib/tross-itest")
		os.RemoveAll(stage)
	})
}

// startUnit запускает службу и ждёт, пока монитор поднимет каналы. Type=notify:
// systemctl start возвращается только после READY=1.
func startUnit(t *testing.T) {
	t.Helper()
	began := time.Now()
	systemctl(t, "start", itestUnit)
	t.Logf("measure: systemctl start returned in %v", time.Since(began).Round(100*time.Millisecond))
	until(t, 15*time.Second, "all links up", func() bool {
		out, err := exec.Command("wget", "-q", "-T", "2", "-O", "-", "http://192.168.77.1:8080/api/links").Output()
		return err == nil && strings.Count(string(out), `"state":"up"`) == 3
	})
	// Песочница службы не мешает источникам реестра (сырой сокет DHCP —
	// AF_PACKET, соседи — netlink, группы multicast).
	out, _ := exec.Command("journalctl", "-u", itestUnit, "-o", "cat", "--since", "@"+strconv.FormatInt(began.Unix(), 10)).Output()
	if strings.Contains(string(out), "source stopped") || strings.Contains(string(out), "LAN sources not started") {
		t.Errorf("device sources failed under the unit:\n%s", out)
	}
}

// withMainDefault — маршрут по умолчанию в основной таблице, как у системы
// мини-ПК (DHCP основного канала): без демона сеть идёт через него.
func withMainDefault(t *testing.T) {
	t.Helper()
	if out, err := exec.Command("ip", "route", "replace", "default", "via", "100.64.1.1", "dev", "wan1").CombinedOutput(); err != nil {
		t.Fatalf("main default route: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "route", "del", "default", "via", "100.64.1.1", "dev", "wan1").Run() })
}

func ownedRuleCount(t *testing.T) int {
	t.Helper()
	out, err := exec.Command("ip", "rule").Output()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for line := range strings.Lines(string(out)) {
		pref, _, _ := strings.Cut(line, ":")
		if p, err := strconv.Atoi(pref); err == nil && p >= 10000 && p < 10256 {
			n++
		}
	}
	return n
}

func nftHas(table string) bool {
	return exec.Command("nft", "list", "table", "inet", table).Run() == nil
}

func TestServiceStopFailsOpen(t *testing.T) {
	installUnit(t)
	withMainDefault(t)
	startUnit(t)
	if via := fetchVia(t, 200_000); via == "" {
		t.Fatal("no traffic with the daemon running")
	}
	systemctl(t, "stop", itestUnit)
	if n := ownedRuleCount(t); n != 0 {
		t.Fatalf("ip rules left after stop: %d", n)
	}
	if nftHas("tross") {
		t.Fatal("policy table left after stop")
	}
	if !nftHas("tross_nat") {
		t.Fatal("NAT must stay after stop (fail-open)")
	}
	if via := fetchVia(t, 200_000); via != "wan1" {
		t.Fatalf("without the daemon traffic must go via main default (wan1), got %q", via)
	}
}

func TestServiceRestartsAfterKill(t *testing.T) {
	installUnit(t)
	withMainDefault(t)
	startUnit(t)
	pid := unitProp(t, "MainPID")
	restarts, _ := strconv.Atoi(unitProp(t, "NRestarts"))
	killed := time.Now()
	systemctl(t, "kill", "--kill-whom=main", "-s", "SIGKILL", itestUnit)
	until(t, 20*time.Second, "service back after kill -9", func() bool {
		n, _ := strconv.Atoi(unitProp(t, "NRestarts"))
		return n == restarts+1 && unitProp(t, "ActiveState") == "active" && unitProp(t, "MainPID") != pid
	})
	t.Logf("measure: kill -9 → service active again in %v", time.Since(killed).Round(100*time.Millisecond))
	// Между падением и перезапуском ExecStopPost снял разметку упавшего процесса.
	logs, _ := exec.Command("journalctl", "-u", itestUnit, "-o", "cat", "--since", "@"+strconv.FormatInt(killed.Unix()-1, 10)).Output()
	if !strings.Contains(string(logs), "trossd cleanup done") {
		t.Fatalf("ExecStopPost cleanup did not run after kill -9:\n%s", logs)
	}
	if n := ownedRuleCount(t); n != 4 {
		t.Fatalf("ip rules after restart = %d, want 4", n)
	}
	until(t, 15*time.Second, "traffic after restart", func() bool { return fetchVia(t, 200_000) != "" })
}

func TestServiceWatchdogRestartsHungDaemon(t *testing.T) {
	installUnit(t)
	withMainDefault(t)
	startUnit(t)
	pid := unitProp(t, "MainPID")
	restarts, _ := strconv.Atoi(unitProp(t, "NRestarts"))
	hung := time.Now()
	// Замороженный процесс не шлёт WATCHDOG=1: systemd должен его убить и поднять заново.
	if err := exec.Command("kill", "-STOP", pid).Run(); err != nil {
		t.Fatal(err)
	}
	until(t, 45*time.Second, "service restarted by the watchdog", func() bool {
		n, _ := strconv.Atoi(unitProp(t, "NRestarts"))
		return n == restarts+1 && unitProp(t, "ActiveState") == "active" && unitProp(t, "MainPID") != pid
	})
	t.Logf("measure: hung daemon (WatchdogSec=6) restarted in %v", time.Since(hung).Round(100*time.Millisecond))
}

func TestServiceRestartKeepsEstablishedDownload(t *testing.T) {
	installUnit(t)
	withMainDefault(t)
	lab(t, "shape", "isp1", "8", "1", "0", "16", "0")
	t.Cleanup(func() { lab(t, "shape", "isp1", "8", "1", "0", "0", "0") })
	startUnit(t)

	const size = 30_000_000 // ~15 с при 16 Мбит/с
	result := make(chan int, 1)
	go func() {
		out, _ := exec.Command("ip", "netns", "exec", "tl-client", "sh", "-c",
			"wget -q -T 30 --tries=1 -O - 'http://"+benchSrv+"/bytes?n="+strconv.Itoa(size)+"' | wc -c").Output()
		n, _ := strconv.Atoi(strings.TrimSpace(string(out)))
		result <- n
	}()
	time.Sleep(3 * time.Second)
	began := time.Now()
	systemctl(t, "restart", itestUnit)
	t.Logf("measure: systemctl restart returned in %v", time.Since(began).Round(100*time.Millisecond))
	select {
	case n := <-result:
		if n != size {
			t.Fatalf("download broken by service restart: %d of %d bytes", n, size)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("download did not finish")
	}
}
