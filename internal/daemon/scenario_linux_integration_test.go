//go:build linux && integration

// Сценарии отказоустойчивости Этапа 1: демон целиком в реальном режиме
// внутри tl-tross, трафик — из tl-client, обрывы — scripts/lab-netns.
package daemon

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"tross/core/model"
	"tross/internal/config"
)

const benchSrv = "203.0.113.10"

var wans = []string{"wan1", "wan2", "wan3"}

func labCfg(t *testing.T) *config.Config {
	t.Helper()
	path := "configs/lab.yaml"
	if _, err := os.Stat(path); err != nil {
		path = "../../configs/lab.yaml"
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// startDaemon запускает демон и ждёт, пока монитор поднимет все каналы.
func startDaemon(t *testing.T, cfg *config.Config) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{Config: cfg, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Version: "itest"})
	}()
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("daemon Run: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("daemon did not stop")
		}
	}
	t.Cleanup(stop)
	until(t, 15*time.Second, "all links up", func() bool {
		out, err := exec.Command("wget", "-q", "-T", "2", "-O", "-", "http://"+cfg.API.Listen+"/api/links").Output()
		return err == nil && strings.Count(string(out), `"state":"up"`) == 3
	})
	return stop
}

func until(t *testing.T, limit time.Duration, what string, cond func() bool) time.Duration {
	t.Helper()
	start := time.Now()
	for !cond() {
		if time.Since(start) > limit {
			t.Fatalf("%s: not reached within %v", what, limit)
		}
		time.Sleep(250 * time.Millisecond)
	}
	return time.Since(start)
}

func lab(t *testing.T, args ...string) {
	t.Helper()
	l := os.Getenv("LAB_NETNS")
	if l == "" {
		t.Fatal("LAB_NETNS is not set (run via scripts/lab-itest)")
	}
	if out, err := exec.Command(l, args...).CombinedOutput(); err != nil {
		t.Fatalf("lab-netns %v: %v\n%s", args, err, out)
	}
}

func rx(t *testing.T) map[string]int64 {
	t.Helper()
	m := map[string]int64{}
	for _, w := range wans {
		b, err := os.ReadFile("/sys/class/net/" + w + "/statistics/rx_bytes")
		if err != nil {
			t.Fatal(err)
		}
		m[w], _ = strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	}
	return m
}

// fetchVia скачивает n байт с сервера стенда; возвращает канал, принёсший
// загрузку ("" — не удалась).
func fetchVia(t *testing.T, n int) string {
	t.Helper()
	before := rx(t)
	out, err := exec.Command("ip", "netns", "exec", "tl-client", "sh", "-c",
		"wget -q -T 2 --tries=1 -O - 'http://"+benchSrv+"/bytes?n="+strconv.Itoa(n)+"' | wc -c").Output()
	got, _ := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil || got != n {
		return ""
	}
	after := rx(t)
	for _, w := range wans {
		if after[w]-before[w] >= int64(n) {
			return w
		}
	}
	return ""
}

func waitVia(t *testing.T, want string, limit time.Duration) time.Duration {
	t.Helper()
	return until(t, limit, "new connections via "+want, func() bool { return fetchVia(t, 200_000) == want })
}

func TestFailoverAndRecovery(t *testing.T) {
	startDaemon(t, labCfg(t))
	if got := fetchVia(t, 500_000); got != "wan1" {
		t.Fatalf("initial path %q, want wan1 (isp1 has priority)", got)
	}

	lab(t, "break", "isp1", "loss")
	t.Cleanup(func() { lab(t, "restore", "isp1") })
	d := waitVia(t, "wan2", 15*time.Second)
	t.Logf("measure: failover isp1 → isp2 in %v", d.Round(100*time.Millisecond))
	if d > 12*time.Second {
		t.Errorf("failover took %v, want ≤ 10 s detection + apply", d)
	}

	lab(t, "break", "isp2", "loss")
	t.Cleanup(func() { lab(t, "restore", "isp2") })
	d = waitVia(t, "wan3", 15*time.Second)
	t.Logf("measure: both wired down → LTE in %v", d.Round(100*time.Millisecond))

	lab(t, "restore", "isp2")
	d = waitVia(t, "wan2", 40*time.Second)
	t.Logf("measure: back to isp2 in %v", d.Round(100*time.Millisecond))
	if d < 16*time.Second {
		t.Errorf("isp2 returned after %v — earlier than recover_after allows", d)
	}
	lab(t, "restore", "isp1")
	d = waitVia(t, "wan1", 40*time.Second)
	t.Logf("measure: back to isp1 in %v", d.Round(100*time.Millisecond))
}

// TestUDPFlowResumesAfterFailover — игровой UDP-поток: после обрыва канала
// сброс соединений даёт следующим пакетам клиента новый путь; без него поток
// застрял бы в мёртвом канале до таймаута conntrack (для UDP — до 2 минут).
func TestUDPFlowResumesAfterFailover(t *testing.T) {
	startDaemon(t, labCfg(t))
	bin := os.Getenv("LAB_NETNS")
	labsrv := bin[:strings.LastIndex(bin, "/scripts/")] + "/bin/labsrv"
	res := make(chan string, 1)
	before := rx(t)
	go func() {
		out, _ := exec.Command("ip", "netns", "exec", "tl-client", labsrv, "udpping",
			"-target", benchSrv+":9000", "-rate", "20", "-n", "500", "-wait", "2s").CombinedOutput()
		res <- strings.TrimSpace(string(out))
	}()
	time.Sleep(3 * time.Second)
	lab(t, "break", "isp1", "loss")
	t.Cleanup(func() { lab(t, "restore", "isp1") })
	out := <-res
	after := rx(t)
	t.Logf("measure: game-like UDP across failover: %s", out)
	f := strings.Fields(out) // sent N, received M, ...
	if len(f) < 4 {
		t.Fatalf("udpping output: %q", out)
	}
	got, _ := strconv.Atoi(strings.TrimSuffix(f[3], ","))
	// 25 с потока, обрыв ~на 3-й с, обнаружение ≤ 10 с — должно дойти больше половины.
	if got < 250 {
		t.Errorf("only %d of 500 UDP packets got through — flow did not resume", got)
	}
	if after["wan2"]-before["wan2"] < 10_000 {
		t.Errorf("UDP flow did not move to isp2 (wan2 +%d B)", after["wan2"]-before["wan2"])
	}
}

// TestFailoverCutsStuckUpload — отдача на умершем канале обрывается быстро
// (клиент сам шлёт пакеты: после сброса соединения сервер отвечает RST через
// новый канал) и может сразу повториться. Загрузку, где клиент только
// принимает, так оборвать нельзя — она ждёт таймаута приложения (см.
// docs/CONTEXT_dataplane.md).
func TestFailoverCutsStuckUpload(t *testing.T) {
	lab(t, "shape", "isp1", "8", "1", "0", "0", "16")
	t.Cleanup(func() { lab(t, "shape", "isp1", "8", "1", "0", "0", "0") })
	startDaemon(t, labCfg(t))
	bin := os.Getenv("LAB_NETNS")
	labsrv := bin[:strings.LastIndex(bin, "/scripts/")] + "/bin/labsrv"

	ended := make(chan time.Time, 1)
	var out []byte
	go func() {
		out, _ = exec.Command("ip", "netns", "exec", "tl-client", labsrv, "upload",
			"-url", "http://"+benchSrv+"/sink", "-n", "50000000", "-timeout", "60s").CombinedOutput()
		ended <- time.Now()
	}()
	time.Sleep(3 * time.Second)
	broke := time.Now()
	lab(t, "break", "isp1", "loss")
	t.Cleanup(func() { lab(t, "restore", "isp1") })
	select {
	case at := <-ended:
		t.Logf("measure: upload on failed link ended %v after failure: %s", at.Sub(broke).Round(100*time.Millisecond), strings.TrimSpace(string(out)))
		if at.Sub(broke) > 15*time.Second {
			t.Errorf("upload hung %v after failure", at.Sub(broke))
		}
	case <-time.After(30 * time.Second):
		t.Fatal("upload on the failed link was not cut (connections not flushed)")
	}
	if got := fetchVia(t, 2_000_000); got != "wan2" {
		t.Fatalf("retry after failover went %q, want wan2", got)
	}
}
func TestFlappingLinkStaysOut(t *testing.T) {
	startDaemon(t, labCfg(t))
	lab(t, "break", "isp1", "loss")
	t.Cleanup(func() { lab(t, "restore", "isp1") })
	waitVia(t, "wan2", 15*time.Second)

	end := time.Now().Add(30 * time.Second)
	broken := true
	for time.Now().Before(end) {
		if broken {
			lab(t, "restore", "isp1")
		} else {
			lab(t, "break", "isp1", "loss")
		}
		broken = !broken
		time.Sleep(3 * time.Second)
		if got := fetchVia(t, 200_000); got == "wan1" {
			t.Fatal("flapping isp1 was taken back into service")
		}
	}
	lab(t, "restore", "isp1")
	d := waitVia(t, "wan1", 40*time.Second)
	t.Logf("measure: isp1 back %v after flapping stopped", d.Round(100*time.Millisecond))
}

func TestRestartKeepsEstablishedDownload(t *testing.T) {
	lab(t, "shape", "isp1", "8", "1", "0", "16", "0")
	t.Cleanup(func() { lab(t, "shape", "isp1", "8", "1", "0", "0", "0") })
	cfg := labCfg(t)
	stop := startDaemon(t, cfg)

	const size = 30_000_000 // ~15 с при 16 Мбит/с
	result := make(chan int, 1)
	go func() {
		out, _ := exec.Command("ip", "netns", "exec", "tl-client", "sh", "-c",
			"wget -q -T 30 --tries=1 -O - 'http://"+benchSrv+"/bytes?n="+strconv.Itoa(size)+"' | wc -c").Output()
		n, _ := strconv.Atoi(strings.TrimSpace(string(out)))
		result <- n
	}()
	time.Sleep(3 * time.Second)
	restart := time.Now()
	stop()
	startDaemon(t, cfg)
	t.Logf("measure: daemon restart (stop → links up) took %v", time.Since(restart).Round(100*time.Millisecond))

	select {
	case n := <-result:
		if n != size {
			t.Fatalf("download broken by restart: %d of %d bytes", n, size)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("download did not finish")
	}
}

func TestBalancedSplitSkipsFallback(t *testing.T) {
	cfg := labCfg(t)
	for i := range cfg.Classes {
		if cfg.Classes[i].ID == model.ClassDefault {
			cfg.Classes[i].Selector = model.SelectBalanced
		}
	}
	startDaemon(t, cfg)
	before := rx(t)
	if out, err := exec.Command("ip", "netns", "exec", "tl-client", "sh", "-c",
		"for i in $(seq 64 127); do ping -c1 -W1 -s 1000 203.0.113.$i >/dev/null; done").CombinedOutput(); err != nil {
		t.Fatalf("pings: %v %s", err, out)
	}
	after := rx(t)
	d1, d2, d3 := after["wan1"]-before["wan1"], after["wan2"]-before["wan2"], after["wan3"]-before["wan3"]
	share := float64(d1) / float64(d1+d2)
	t.Logf("measure: balanced split wan1 %.0f%% / wan2 %.0f%%, lte +%d B (probes only)", share*100, (1-share)*100, d3)
	if share < 0.25 || share > 0.75 {
		t.Errorf("split %.0f%% / %.0f%% — too uneven", share*100, (1-share)*100)
	}
	// Через LTE — только пробы монитора (сотни байт), не 64 КБ клиентских ping.
	if d3 > 20_000 {
		t.Errorf("fallback LTE carried client traffic: +%d B", d3)
	}
}
