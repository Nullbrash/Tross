//go:build linux && integration

// Интеграционные тесты dataplane на закрытом стенде: бинарник запускается
// внутри netns tl-tross (scripts/lab-itest), трафик идёт из tl-client.
package dataplane

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"tross/core/model"
)

const srv = "203.0.113.10"

func standSpec() Spec {
	link := func(id, iface string, prio, i int) LinkSpec {
		return LinkSpec{
			Link:    model.Link{ID: model.LinkID(id), Interface: iface, Priority: prio},
			Table:   100 + i,
			FwMark:  uint32(i) << 8,
			Gateway: netip.MustParseAddr("100.64." + strconv.Itoa(i) + ".1"),
		}
	}
	return Spec{
		LANInterface: "lan",
		LANNetworks:  []netip.Prefix{netip.MustParsePrefix("192.168.77.0/24")},
		Links:        []LinkSpec{link("isp1", "wan1", 10, 1), link("isp2", "wan2", 20, 2), link("lte", "wan3", 100, 3)},
	}
}

func newSystem(t *testing.T) *System {
	t.Helper()
	if _, err := netlink.LinkByName("wan1"); err != nil {
		t.Fatalf("not on the bench (run via scripts/lab-itest inside tl-tross): %v", err)
	}
	dp, err := NewSystem(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	s := dp.(*System)
	t.Cleanup(func() { _ = s.Teardown(context.Background()) })
	return s
}

func run(t *testing.T, name string, args ...string) (string, error) {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}

func inClient(t *testing.T, shell string) (string, error) {
	t.Helper()
	return run(t, "ip", "netns", "exec", "tl-client", "sh", "-c", shell)
}

func rxBytes(t *testing.T, iface string) int64 {
	t.Helper()
	b, err := os.ReadFile("/sys/class/net/" + iface + "/statistics/rx_bytes")
	if err != nil {
		t.Fatal(err)
	}
	n, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return n
}

// fetch скачивает n байт с сервера стенда; результат — число полученных байт.
func fetch(t *testing.T, n int) (int, error) {
	t.Helper()
	out, err := inClient(t, "wget -q -T 5 --tries=1 -O - 'http://"+srv+"/bytes?n="+strconv.Itoa(n)+"' | wc -c")
	got, _ := strconv.Atoi(strings.TrimSpace(out))
	return got, err
}

func ownedRules(t *testing.T) []netlink.Rule {
	t.Helper()
	all, err := netlink.RuleList(unix.AF_INET)
	if err != nil {
		t.Fatal(err)
	}
	var out []netlink.Rule
	for _, r := range all {
		if r.Priority >= rulePrefBase && r.Priority < rulePrefBase+rulePrefSpan {
			out = append(out, r)
		}
	}
	return out
}

func TestSetupTeardownIdempotent(t *testing.T) {
	ctx := context.Background()
	s := newSystem(t)
	svmBefore, _ := readSysctl(sysctlSVM)

	start := time.Now()
	if err := s.Setup(ctx, standSpec()); err != nil {
		t.Fatal(err)
	}
	t.Logf("measure: Setup took %v", time.Since(start))
	if err := s.Setup(ctx, standSpec()); err != nil {
		t.Fatalf("second Setup: %v", err)
	}
	if n := len(ownedRules(t)); n != 4 {
		t.Fatalf("owned ip rules = %d, want 4 (suppress + 3 links) — Setup must not duplicate", n)
	}
	if out, err := run(t, "nft", "list", "table", "inet", "tross"); err != nil || !strings.Contains(out, "masquerade") {
		t.Fatalf("nft table missing: %v\n%s", err, out)
	}
	if out, _ := run(t, "ip", "route", "show", "table", "101"); !strings.Contains(out, "default via 100.64.1.1 dev wan1") {
		t.Fatalf("table 101: %q", out)
	}
	if v, _ := readSysctl(sysctlSVM); v != "1" {
		t.Fatalf("src_valid_mark = %s", v)
	}

	if err := s.Teardown(ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(ownedRules(t)); n != 0 {
		t.Fatalf("rules left after Teardown: %d", n)
	}
	if _, err := run(t, "nft", "list", "table", "inet", "tross"); err == nil {
		t.Fatal("nft table left after Teardown")
	}
	for _, tbl := range []string{"101", "102", "103"} {
		if out, _ := run(t, "ip", "route", "show", "table", tbl); strings.TrimSpace(out) != "" {
			t.Fatalf("table %s not empty: %q", tbl, out)
		}
	}
	if v, _ := readSysctl(sysctlSVM); v != svmBefore {
		t.Fatalf("src_valid_mark = %s, want restored %s", v, svmBefore)
	}
}

func TestNewConnectionsFollowUsableLinks(t *testing.T) {
	ctx := context.Background()
	s := newSystem(t)
	if err := s.Setup(ctx, standSpec()); err != nil {
		t.Fatal(err)
	}
	via := func(want string) {
		t.Helper()
		before := map[string]int64{}
		for _, w := range []string{"wan1", "wan2", "wan3"} {
			before[w] = rxBytes(t, w)
		}
		if got, err := fetch(t, 500_000); err != nil || got != 500_000 {
			t.Fatalf("fetch via %s: got %d bytes, %v", want, got, err)
		}
		for _, w := range []string{"wan1", "wan2", "wan3"} {
			d := rxBytes(t, w) - before[w]
			if w == want && d < 500_000 {
				t.Fatalf("%s carried only %d bytes, expected the download", w, d)
			}
			if w != want && d > 50_000 {
				t.Fatalf("%s carried %d bytes, expected only %s", w, d, want)
			}
		}
	}
	via("wan1")
	if out, err := inClient(t, "ping -c 20 -i 0.2 -W 2 "+srv+" | tail -1"); err == nil {
		t.Logf("measure: rtt via isp1 with dataplane rules: %s", strings.TrimSpace(out))
	}

	start := time.Now()
	if err := s.SetLinkUsable(ctx, "isp1", false); err != nil {
		t.Fatal(err)
	}
	t.Logf("measure: SetLinkUsable took %v", time.Since(start))
	via("wan2")
	if err := s.SetLinkUsable(ctx, "isp2", false); err != nil {
		t.Fatal(err)
	}
	via("wan3")
	if err := s.SetLinkUsable(ctx, "lte", false); err != nil {
		t.Fatal(err)
	}
	// На стенде в main нет маршрута по умолчанию: без пригодных каналов связи нет.
	if got, err := fetch(t, 1000); err == nil && got == 1000 {
		t.Fatal("no usable links, yet the fetch succeeded")
	}
	if err := s.SetLinkUsable(ctx, "isp2", true); err != nil {
		t.Fatal(err)
	}
	via("wan2")
	if err := s.SetLinkUsable(ctx, "isp1", true); err != nil {
		t.Fatal(err)
	}
	via("wan1")
}

func TestEstablishedStaysThenFlushKills(t *testing.T) {
	ctx := context.Background()
	s := newSystem(t)
	lab := os.Getenv("LAB_NETNS")
	if lab == "" {
		t.Fatal("LAB_NETNS (path to scripts/lab-netns) is not set")
	}
	// isp1 сужается до 16 Мбит/с, чтобы загрузка длилась ~25 с.
	if out, err := run(t, lab, "shape", "isp1", "8", "1", "0", "16", "0"); err != nil {
		t.Fatalf("shape: %v\n%s", err, out)
	}
	t.Cleanup(func() { _, _ = run(t, lab, "shape", "isp1", "8", "1", "0", "0", "0") })
	if err := s.Setup(ctx, standSpec()); err != nil {
		t.Fatal(err)
	}

	const size = 50_000_000
	type result struct {
		got int
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := inClient(t, "wget -q -T 5 --tries=1 -O - 'http://"+srv+"/bytes?n="+strconv.Itoa(size)+"' | wc -c")
		got, _ := strconv.Atoi(strings.TrimSpace(out))
		done <- result{got, err}
	}()
	time.Sleep(3 * time.Second)

	if err := s.SetLinkUsable(ctx, "isp1", false); err != nil {
		t.Fatal(err)
	}
	w1, w2 := rxBytes(t, "wan1"), rxBytes(t, "wan2")
	time.Sleep(3 * time.Second)
	d1, d2 := rxBytes(t, "wan1")-w1, rxBytes(t, "wan2")-w2
	if d1 < 2_000_000 {
		t.Fatalf("established download left wan1 after link became unusable: wan1 +%d, wan2 +%d", d1, d2)
	}
	if d2 > 100_000 {
		t.Fatalf("wan2 got %d bytes — established connection moved", d2)
	}
	t.Logf("established connection stayed on wan1: +%d bytes in 3 s", d1)

	if err := s.FlushConntrack(ctx, "isp1"); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		if r.got >= size {
			t.Fatalf("download completed (%d bytes) despite conntrack flush", r.got)
		}
		t.Logf("download cut after flush at %d of %d bytes", r.got, size)
	case <-time.After(20 * time.Second):
		t.Fatal("download still running 20 s after conntrack flush")
	}
}

// TestMeasureForwarding — замер ЦП пересылки с правилами демона (пакеты по
// MTU), для сравнения с пустым стендом. Только по LAB_MEASURE_OUT.
func TestMeasureForwarding(t *testing.T) {
	out := os.Getenv("LAB_MEASURE_OUT")
	if out == "" {
		t.Skip("set LAB_MEASURE_OUT=<dir> to run the measurement")
	}
	ctx := context.Background()
	s := newSystem(t)
	lab := os.Getenv("LAB_NETNS")
	measureBin := filepath.Join(filepath.Dir(lab), "..", "bin", "labmeasure")
	if o, err := run(t, lab, "offload", "off"); err != nil {
		t.Fatalf("offload off: %v\n%s", err, o)
	}
	t.Cleanup(func() { _, _ = run(t, lab, "offload", "on") })
	if err := s.Setup(ctx, standSpec()); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"down", "up"} {
		m := exec.Command(measureBin, "-out", filepath.Join(out, "dataplane-isp1-"+dir), "-duration", "24s", "-netns", "tl-tross")
		var mout strings.Builder
		m.Stdout = &mout
		if err := m.Start(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Second)
		args := "iperf3 -c " + srv + " -t 20 -P 4"
		if dir == "down" {
			args += " -R"
		}
		res, err := inClient(t, args+" | grep -E 'SUM.*receiver'")
		if err != nil {
			t.Fatalf("iperf3 %s: %v\n%s", dir, err, res)
		}
		_ = m.Wait()
		t.Logf("measure %s: %s", dir, strings.TrimSpace(res))
		for line := range strings.Lines(mout.String()) {
			if strings.HasPrefix(line, "cpu") || strings.HasPrefix(line, "temp") {
				t.Logf("measure %s: %s", dir, strings.TrimSpace(line))
			}
		}
	}
}

func TestAddToSet(t *testing.T) {
	ctx := context.Background()
	s := newSystem(t)
	if err := s.Setup(ctx, standSpec()); err != nil {
		t.Fatal(err)
	}
	if err := s.AddToSet(ctx, SetDPI, netip.MustParseAddr("203.0.113.99"), time.Minute); err != nil {
		t.Fatal(err)
	}
	out, err := run(t, "nft", "list", "set", "inet", "tross", string(SetDPI))
	if err != nil || !strings.Contains(out, "203.0.113.99") || !strings.Contains(out, "expires") {
		t.Fatalf("set content: %v\n%s", err, out)
	}
	if err := s.AddToSet(ctx, "nope", netip.MustParseAddr("203.0.113.1"), time.Minute); err == nil {
		t.Fatal("unknown set must be rejected")
	}
}
