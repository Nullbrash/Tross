//go:build linux && integration && extra

// Замер реестра устройств на стенде (только по LAB_MEASURE_OUT): время
// «подключилось по DHCP → в реестре с адресом», память на устройство,
// поток анонсов mDNS, размер записи для оценки записи на SSD.
package daemon

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"tross/internal/config"
)

func rssKB(t *testing.T) int {
	t.Helper()
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "VmRSS:"); ok {
			var kb int
			fmt.Sscan(strings.TrimSuffix(strings.TrimSpace(v), " kB"), &kb)
			return kb
		}
	}
	return 0
}

func heapMB() float64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return float64(m.HeapAlloc) / 1e6
}

func cpuTime() time.Duration {
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

func TestMeasureDevices(t *testing.T) {
	out := os.Getenv("LAB_MEASURE_OUT")
	if out == "" {
		t.Fatal("set LAB_MEASURE_OUT=<dir> for the measurement output")
	}
	dir := "/run/tross-dhcp-measure"
	_ = os.RemoveAll(dir)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	cfg := classCfg(t)
	d := &cfg.LAN.DHCP
	d.Enabled, d.Range, d.Lease, d.Gateway = true, "192.168.77.20-192.168.77.250", 10*time.Minute, netip.MustParseAddr("192.168.77.1")
	d.Dir, d.PIDFile, d.Unit = dir, filepath.Join(dir, "dnsmasq.pid"), "none"
	stop := startDaemon(t, cfg)
	defer stop()
	conf := filepath.Join(dir, "dnsmasq.conf")
	until(t, 10*time.Second, "dnsmasq config", func() bool { _, err := os.Stat(conf); return err == nil })
	if out, err := inNS("tl-tross", "dnsmasq --conf-file="+conf); err != nil {
		t.Fatalf("dnsmasq: %v %s", err, out)
	}
	t.Cleanup(func() { _, _ = inNS("tl-tross", "kill $(cat "+d.PIDFile+")") })
	var lines []string
	logf := func(format string, a ...any) {
		s := fmt.Sprintf(format, a...)
		t.Log("measure: " + s)
		lines = append(lines, s)
	}

	// Время: DHCP-обмен закончен → запись с адресом в API.
	var lat []time.Duration
	for i := range 20 {
		mac := fmt.Sprintf("a6:00:00:00:01:%02x", i)
		ip, _ := dhcpc(t, mac, fmt.Sprintf("join-%d", i))
		start := time.Now()
		id := "dev-" + strings.ReplaceAll(mac, ":", "")
		for {
			if dev, ok := apiDevice(t, cfg, id); ok && dev.Addr == ip {
				break
			}
			if time.Since(start) > 10*time.Second {
				t.Fatalf("%s not in the registry", mac)
			}
			time.Sleep(10 * time.Millisecond)
		}
		lat = append(lat, time.Since(start))
	}
	slices.Sort(lat)
	logf("dhcp → registry with address: p50 %v, max %v (20 devices; poll 10 ms)", lat[len(lat)/2].Round(time.Millisecond), lat[len(lat)-1].Round(time.Millisecond))

	// Память на устройство.
	h0, r0 := heapMB(), rssKB(t)
	const n = 200
	start := time.Now()
	for i := range n {
		dhcpc(t, fmt.Sprintf("a6:00:00:00:02:%02x", i), fmt.Sprintf("dev-%d", i))
	}
	took := time.Since(start)
	until(t, 10*time.Second, "all devices", func() bool { return len(apiDevices(t, cfg)) >= n+20 })
	h1, r1 := heapMB(), rssKB(t)
	logf("%d devices by DHCP in %v; heap %.1f → %.1f MB (%.1f KB/device), RSS %d → %d KB", n, took.Round(time.Millisecond), h0, h1, (h1-h0)*1000/n, r0, r1)

	// Поток анонсов mDNS с одного устройства (как шумный ТВ или атака).
	c0, w0 := cpuTime(), time.Now()
	const flood = 20000
	if out, err := inNS("tl-client", labsrvBin(t)+fmt.Sprintf(" announce -mdns lab-client -addr %s -count %d", benchClient, flood)); err != nil {
		t.Fatalf("flood: %v %s", err, out)
	}
	wall := time.Since(w0)
	cpu := cpuTime() - c0
	t0 := time.Now()
	apiDevices(t, cfg)
	logf("mDNS flood: %d packets in %v (%.0f/s); daemon CPU %v (%.0f%% of one core); API during/after: %v",
		flood, wall.Round(time.Millisecond), float64(flood)/wall.Seconds(), cpu.Round(time.Millisecond), 100*cpu.Seconds()/wall.Seconds(), time.Since(t0).Round(time.Millisecond))

	// Запись на SSD: «последний раз в сети» — пачкой раз в 5 мин.
	ds := apiDevices(t, cfg)
	var total int
	for _, dv := range ds {
		b, _ := json.Marshal(dv)
		total += len(b)
	}
	avg := total / len(ds)
	logf("device record ~%d bytes; LastSeen flush every 5 min: %.1f MB/day per 30 online devices, %.1f MB/day per %d (plus WAL ×~2)",
		avg, float64(avg*30*288)/1e6, float64(avg*len(ds)*288)/1e6, len(ds))
	if err := os.WriteFile(filepath.Join(out, "devices.txt"), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Error(err)
	}
}

func apiDevices(t *testing.T, cfg *config.Config) []map[string]any {
	t.Helper()
	resp, err := itest.do("GET", "/api/devices", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var v struct{ Devices []map[string]any }
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v.Devices
}
