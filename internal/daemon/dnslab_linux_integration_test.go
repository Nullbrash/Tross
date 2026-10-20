//go:build linux && integration

// Резолвер на стенде с «резолверами» разного поведения (labsrv dns в
// lab-netns: 203.0.113.54 — свой адрес на имя, .55 — он же с задержкой
// 150 мс, .56 — SERVFAIL, .57 — молчит), сторож, списки из кеша, классы и
// корзины по домену, перехват DNS на канале.
package daemon

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"tross/core/dns"
	corelists "tross/core/lists"
	"tross/core/model"
	"tross/internal/config"
	"tross/internal/dataplane"
)

const labDNSCA = "/run/tross-lab/dns-ca.pem"

// hashNet — адреса «резолвера» hash: у каждого имени свой.
var hashNet = netip.MustParsePrefix("198.51.100.0/24")

func hashCfg(t *testing.T, ups ...config.Upstream) *config.Config {
	t.Helper()
	cfg := classCfg(t)
	if len(ups) == 0 {
		ups = []config.Upstream{{Name: "hash", URL: "https://203.0.113.54/dns-query", Pools: []dns.Pool{dns.PoolProtected, dns.PoolFast}}}
	}
	cfg.DNS.Upstreams = ups
	cfg.DNS.CAFile = labDNSCA
	return cfg
}

func digAddr(t *testing.T, name string) netip.Addr {
	t.Helper()
	got := dig(t, "192.168.77.1", name, "")
	a, err := netip.ParseAddr(got)
	if err != nil || !hashNet.Contains(a) {
		t.Fatalf("%s: answer %q, want an address in %v", name, got, hashNet)
	}
	return a
}

func apiDNS(t *testing.T, cfg *config.Config) (v struct {
	Serving   string
	Upstreams []dns.UpstreamHealth
	Links     []struct {
		Link        string
		Intercepted *bool
	}
}) {
	t.Helper()
	getJSON(t, "http://"+cfg.API.Listen+"/api/dns", &v)
	return v
}

// Гонка быстрого набора уходит от молчащего и отвечающего SERVFAIL к
// быстрому; особо личное — только защищённым: основной молчит — отвечает
// его назначенный запасной.
func TestDNSUpstreamFailures(t *testing.T) {
	cfg := hashCfg(t,
		config.Upstream{Name: "ok", URL: "https://203.0.113.54/dns-query", Pools: []dns.Pool{dns.PoolFast}},
		config.Upstream{Name: "slow", URL: "https://203.0.113.55/dns-query", Pools: []dns.Pool{dns.PoolFast}},
		config.Upstream{Name: "servfail", URL: "tls://203.0.113.56", Pools: []dns.Pool{dns.PoolFast}},
		config.Upstream{Name: "mute", URL: "https://203.0.113.57/dns-query", Pools: []dns.Pool{dns.PoolFast, dns.PoolProtected}, Backup: "ok-dot"},
		config.Upstream{Name: "ok-dot", URL: "tls://203.0.113.54"},
	)
	startDaemon(t, cfg)
	var lat []time.Duration
	for i := range 30 {
		start := time.Now()
		digAddr(t, fmt.Sprintf("n%d.fail.lab.example", i))
		lat = append(lat, time.Since(start))
	}
	slices.Sort(lat[10:])
	med := lat[10+len(lat[10:])/2]
	t.Logf("dig latency (incl. netns exec): first %v, median of the last 20 %v, max %v", lat[0], med, lat[len(lat)-1])
	if med > 100*time.Millisecond {
		t.Errorf("median %v: the race does not settle on the fast server", med)
	}
	// Здоровье — по паре «сервер + канал»; здесь — сумма по каналам.
	health := map[string]dns.UpstreamHealth{}
	for _, h := range apiDNS(t, cfg).Upstreams {
		x := health[h.Upstream]
		x.OK, x.Failed = x.OK+h.OK, x.Failed+h.Failed
		health[h.Upstream] = x
	}
	t.Logf("health: %+v", health)
	for _, name := range []string{"servfail", "mute"} {
		if h := health[name]; h.Failed == 0 {
			t.Errorf("%s: no failures counted: %+v", name, h)
		}
	}
	if h := health["ok-dot"]; h.OK != 0 {
		t.Errorf("ok-dot is only a backup, yet answered %d fast queries", h.OK)
	}

	// Steam — особо личное по умолчанию: защищённый набор — один «mute»,
	// дальше — его запасной.
	start := time.Now()
	digAddr(t, "store.steampowered.com")
	t.Logf("sensitive name via the backup: %v", time.Since(start))
	backupOK := uint64(0)
	for _, h := range apiDNS(t, cfg).Upstreams {
		if h.Upstream == "ok-dot" {
			backupOK += h.OK
		}
	}
	if backupOK == 0 {
		t.Error("sensitive name was not answered by the designated backup")
	}
}

// Сторож: резолвер перестал отвечать (порт 53 мини-ПК закрыт) — за ≤ 15 с
// дом на запасном; открыли — обратно на резолвер.
func TestDNSWatchdogFallback(t *testing.T) {
	cfg := classCfg(t)
	startDaemon(t, cfg)
	until(t, 5*time.Second, "resolver answers", func() bool {
		return dig(t, "192.168.77.1", "printer", "") == "" && dig(t, "192.168.77.1", "store.steampowered.com", "") == benchSrv
	})
	nft := func(args ...string) {
		if out, err := exec.Command("nft", args...).CombinedOutput(); err != nil {
			t.Fatalf("nft %v: %v %s", args, err, out)
		}
	}
	nft("add table inet tltest")
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "inet", "tltest").Run() })
	nft("add chain inet tltest in { type filter hook input priority 0 ; }")
	nft("add rule inet tltest in meta l4proto { tcp, udp } th dport 53 drop")
	// Однословное имя: резолвер — NXDOMAIN, запасной (dnsmasq) — адрес.
	took := until(t, 25*time.Second, "home dns on the fallback", func() bool { return dig(t, "192.168.77.1", "printer", "") == benchSrv })
	t.Logf("resolver silent → fallback answers in %v", took)
	if took > 15*time.Second {
		t.Errorf("fallback after %v, want ≤ 15 s", took)
	}
	nft("delete table inet tltest")
	back := until(t, 25*time.Second, "back on the resolver", func() bool { return dig(t, "192.168.77.1", "printer", "") == "" })
	t.Logf("resolver answers again → back in %v", back)
}

// Онлайн-список: загрузка через канал, класс по домену в ядре; перезапуск
// без источника — список из кеша, адрес снова в множестве класса.
func TestListsFromCacheAfterRestart(t *testing.T) {
	const file = "/run/tross-lab/files/lab-list.txt"
	if err := os.WriteFile(file, []byte("# lab list\nlisted.lab.example\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(file) })
	cfg := hashCfg(t)
	cfg.Lists.Sources = []corelists.Source{{ID: "lab", URL: "http://" + benchSrv + "/files/lab-list.txt", Format: corelists.FormatText, Purpose: model.PurposeClass, Class: "streaming"}}
	set := string(dataplane.ListSet(model.LayerOnline, "streaming"))
	sourceDomains := func() (int, string) {
		var v struct{ Sources []corelists.SourceStatus }
		getJSON(t, "http://"+cfg.API.Listen+"/api/lists", &v)
		for _, s := range v.Sources {
			if s.Source.ID == "lab" {
				return s.Domains, s.Error
			}
		}
		return -1, ""
	}

	stop := startDaemon(t, cfg)
	var lastErr string
	defer func() {
		if t.Failed() {
			t.Logf("last source error: %q", lastErr)
		}
	}()
	until(t, 90*time.Second, "list downloaded (next minute check after the links are up)", func() bool {
		n, e := sourceDomains()
		lastErr = e
		return n == 1
	})
	a := digAddr(t, "www.listed.lab.example")
	if !strings.Contains(nftSet(t, set), a.String()) {
		t.Fatalf("%s: address %v not in %s", "listed.lab.example", a, set)
	}
	udpTo(t, a, "9020")
	if c := connTo(t, cfg, a, 9020); c.Class != "streaming" || c.Tin != "video" {
		t.Errorf("listed domain connection: %+v, want streaming / video", c)
	}
	stop()

	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	startDaemon(t, cfg)
	if n, _ := sourceDomains(); n != 1 {
		t.Fatalf("after restart: %d domains, want the cached list", n)
	}
	out, _ := exec.Command("wget", "-q", "-T", "5", "-O", "-", "--post-data=", "http://"+cfg.API.Listen+"/api/lists/refresh?source=lab").CombinedOutput()
	n, errText := sourceDomains()
	t.Logf("refresh without the source: %s; state: %d domains, error %q", strings.TrimSpace(string(out)), n, errText)
	if n != 1 || errText == "" {
		t.Errorf("failed refresh: %d domains, error %q — want the cached list kept and the error shown", n, errText)
	}
	if b := digAddr(t, "listed.lab.example"); !strings.Contains(nftSet(t, set), b.String()) {
		t.Errorf("after restart: address %v not in %s", b, set)
	}
}

// Классы и корзины по домену: Steam (загрузки и магазин), YouTube, голос
// Discord — из каталога, игра — своим правилом.
func TestDNSClassesByDomain(t *testing.T) {
	cfg := hashCfg(t)
	cfg.Lists.Manual = []config.ListRule{{Domains: []string{"game.lab.example"}, Purpose: model.PurposeClass, Class: "gaming"}}
	startDaemon(t, cfg)
	cases := []struct{ name, class, tin string }{
		{"cache1-fra1.steamcontent.com", "bulk", "bulk"},
		{"store.steampowered.com", "default", "best_effort"},
		{"rr3---sn-abc.googlevideo.com", "streaming", "video"},
		{"lab-voice.discord.media", "voip", "voice"},
		{"eu.game.lab.example", "gaming", "voice"},
	}
	seen := map[netip.Addr]string{}
	for _, c := range cases {
		a := digAddr(t, c.name)
		if prev, ok := seen[a]; ok {
			t.Fatalf("%s and %s share %v: pick other names", prev, c.name, a)
		}
		seen[a] = c.name
		udpTo(t, a, "9020")
		got := connTo(t, cfg, a, 9020)
		t.Logf("%-30s → %v: class %s, tin %s, link %s", c.name, a, got.Class, got.Tin, got.Link)
		if got.Class != c.class || got.Tin != c.tin {
			t.Errorf("%s: class %q tin %q, want %q / %q", c.name, got.Class, got.Tin, c.class, c.tin)
		}
	}
}

// Перехват DNS на канале: провайдер isp2 отвечает на любой обычный DNS
// сам — в /api/dns у isp2 «перехватывает», у isp1 — нет.
func TestDNSInterceptOnLink(t *testing.T) {
	interceptFirst = 3 * time.Second
	t.Cleanup(func() { interceptFirst = time.Minute })
	cmd := exec.Command("ip", "netns", "exec", "tl-isp2", labsrvBin(t), "dns", "-udp", "0.0.0.0:5353=answer:203.0.113.250")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	if out, err := inNS("tl-isp2", "nft add table ip tltest && nft add chain ip tltest pre '{ type nat hook prerouting priority -100 ; }' && nft add rule ip tltest pre udp dport 53 redirect to :5353"); err != nil {
		t.Fatalf("intercepting provider: %v %s", err, out)
	}
	t.Cleanup(func() { _, _ = inNS("tl-isp2", "nft delete table ip tltest") })
	cfg := classCfg(t)
	startDaemon(t, cfg)
	var got map[string]*bool
	until(t, 20*time.Second, "intercept checked", func() bool {
		got = map[string]*bool{}
		for _, l := range apiDNS(t, cfg).Links {
			got[l.Link] = l.Intercepted
		}
		return got["isp1"] != nil && got["isp2"] != nil
	})
	if !*got["isp2"] || *got["isp1"] {
		t.Errorf("intercepted: isp1 %v, isp2 %v — want only isp2", *got["isp1"], *got["isp2"])
	}
}

// udpTo — датаграм с клиента на адрес и порт (эхо labsrv на всех адресах).
func udpTo(t *testing.T, a netip.Addr, port string) {
	t.Helper()
	if out, err := inNS("tl-client", "printf hello > /dev/udp/"+a.String()+"/"+port); err != nil {
		t.Fatalf("udp to %v:%s: %v %s", a, port, err, out)
	}
	time.Sleep(300 * time.Millisecond)
}

type labConn struct {
	Proto, Link, Class, Tin string
	Dst                     netip.AddrPort
}

// connTo — соединение клиента к адресу и порту по снимку conntrack.
func connTo(t *testing.T, cfg *config.Config, a netip.Addr, port uint16) labConn {
	t.Helper()
	out, err := exec.Command("wget", "-q", "-T", "2", "-O", "-", "http://"+cfg.API.Listen+"/api/connections?limit=5000&device="+benchClient).Output()
	if err != nil {
		t.Fatalf("/api/connections: %v", err)
	}
	var v struct{ Connections []labConn }
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatal(err)
	}
	for _, c := range v.Connections {
		if c.Dst == netip.AddrPortFrom(a, port) {
			return c
		}
	}
	t.Fatalf("no connection to %v:%d", a, port)
	return labConn{}
}
