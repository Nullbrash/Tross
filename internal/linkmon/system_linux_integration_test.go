//go:build linux && integration

// Интеграционные тесты монитора на закрытом стенде (scripts/lab-itest):
// процесс работает внутри netns tl-tross, обрывы и ухудшения задаёт
// scripts/lab-netns в netns провайдеров.
package linkmon

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"tross/core/event"
	"tross/core/linkhealth"
	"tross/core/model"
	"tross/internal/dataplane"
)

var (
	t1 = netip.MustParseAddr("203.0.113.1")
	t2 = netip.MustParseAddr("203.0.113.2")
	t3 = netip.MustParseAddr("203.0.113.3") // «белый список» для lte
	// labDNS — DNS стенда: dnsmasq на 53, labsrv — DoT на 853 и DoH на 443
	// с сертификатом, корень которого lab-netns кладёт в labDoHCA.
	labDNS   = netip.MustParseAddr("203.0.113.53")
	labDoHCA = "/run/tross-lab/doh-ca.pem"
	lab      = os.Getenv("LAB_NETNS")
)

func benchLinks() []dataplane.LinkSpec {
	mk := func(id, iface string, i int, kind model.LinkKind) dataplane.LinkSpec {
		return dataplane.LinkSpec{
			Link:    model.Link{ID: model.LinkID(id), Interface: iface, Kind: kind, Priority: i, Metered: kind == model.LinkKindLTE},
			Table:   100 + i,
			FwMark:  uint32(i) << 8,
			Gateway: netip.MustParseAddr("100.64." + strconv.Itoa(i) + ".1"),
		}
	}
	return []dataplane.LinkSpec{
		mk("isp1", "wan1", 1, model.LinkKindWired),
		mk("isp2", "wan2", 2, model.LinkKindWired),
		mk("lte", "wan3", 3, model.LinkKindLTE),
	}
}

type bench struct {
	dp     dataplane.Dataplane
	mon    *System
	bus    *event.Bus
	cancel context.CancelFunc
}

// start поднимает dataplane (таблицы каналов — по ним идут пробы) и монитор.
func start(t *testing.T) *bench { t.Helper(); return startWith(t, nil) }

// startWith — то же с правкой настроек монитора до запуска.
func startWith(t *testing.T, tweak func(*Options)) *bench {
	t.Helper()
	if lab == "" {
		t.Fatal("LAB_NETNS is not set (run via scripts/lab-itest)")
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	dp, err := dataplane.NewSystem(log)
	if err != nil {
		t.Fatal(err)
	}
	specs := benchLinks()
	if err := dp.Setup(context.Background(), dataplane.Spec{LANInterface: "lan", Links: specs}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dp.Teardown(context.Background()) })

	var probes []LinkProbe
	for _, s := range specs {
		p := LinkProbe{Link: s.Link, Mark: s.FwMark, Targets: []netip.Addr{t1, t2, t3}}
		if s.Link.Kind == model.LinkKindLTE {
			p.Targets, p.Whitelist = []netip.Addr{t1, t2}, []netip.Addr{t3}
		}
		probes = append(probes, p)
	}
	bus := event.NewBus()
	opts := Options{
		Log: log, Bus: bus, Interval: 2 * time.Second, Timeout: time.Second,
		Params:     linkhealth.DefaultParams(),
		TCPTargets: []netip.AddrPort{netip.AddrPortFrom(t1, 443), netip.AddrPortFrom(t2, 443)},
		HTTPCheck: HTTPCheckOptions{
			Interval: 4 * time.Second, Timeout: 2 * time.Second,
			DNS:  []DNSServer{{Proto: DNSPlain, Addr: netip.AddrPortFrom(labDNS, 53)}},
			URLs: []HTTPCheckURL{{URL: "http://check.lab/generate_204", Status: 204}},
		},
		// Первый источник недоступен (порт закрыт), второй отвечает заглушкой
		// «ok» — каждый замер проверяет переход на запасной.
		SpeedTest: SpeedTestOptions{URLs: []string{"http://203.0.113.10:81/none", "http://203.0.113.10/", "http://203.0.113.10/bytes?n=200000000"}, Hour: -1, Duration: 6 * time.Second, MaxBytes: 200_000_000},
	}
	if tweak != nil {
		tweak(&opts)
	}
	m, err := NewSystem(opts, probes)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = m.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	b := &bench{dp: dp, mon: m.(*System), bus: bus, cancel: cancel}
	for _, id := range []model.LinkID{"isp1", "isp2", "lte"} {
		b.wait(t, id, model.LinkStateUp, 8*time.Second)
	}
	return b
}

// wait ждёт состояния канала; возвращает момент, когда оно наблюдалось.
func (b *bench) wait(t *testing.T, id model.LinkID, want model.LinkState, limit time.Duration) time.Time {
	t.Helper()
	deadline := time.Now().Add(limit)
	for {
		st, _ := b.mon.Status(id)
		if st.Health.State == want {
			return time.Now()
		}
		if time.Now().After(deadline) {
			// Метрики и возраст снимка отличают «раунды идут, но метрики в норме»
			// от «раунды встали».
			h := st.Health
			t.Fatalf("%s: state %s (%s), want %s within %v; loss %.1f%% rtt %v jitter %v, updated %v ago",
				id, h.State, h.Reason, want, limit, h.Loss*100, h.RTT.Round(100*time.Microsecond),
				h.Jitter.Round(100*time.Microsecond), time.Since(h.UpdatedAt).Round(100*time.Millisecond))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func labCmd(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command(lab, args...).CombinedOutput(); err != nil {
		t.Fatalf("lab-netns %v: %v\n%s", args, err, out)
	}
}

func nftIn(t *testing.T, ns, script string) {
	t.Helper()
	cmd := exec.Command("ip", "netns", "exec", ns, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft in %s: %v\n%s", ns, err, out)
	}
}

func TestLinksUpWithProfileMetrics(t *testing.T) {
	b := start(t)
	before := b.mon.ProbeBytes()
	time.Sleep(10 * time.Second) // 5 раундов
	perRound := float64(b.mon.ProbeBytes()-before) / 5
	for _, id := range []model.LinkID{"isp1", "isp2", "lte"} {
		st, _ := b.mon.Status(id)
		h := st.Health
		t.Logf("measure: %s rtt %v jitter %v loss %.1f%%", id, h.RTT.Round(100*time.Microsecond), h.Jitter.Round(100*time.Microsecond), h.Loss*100)
		lo, hi := 5*time.Millisecond, 20*time.Millisecond
		if id == "lte" {
			lo, hi = 30*time.Millisecond, 80*time.Millisecond
		}
		if h.RTT < lo || h.RTT > hi {
			t.Errorf("%s rtt %v outside profile [%v, %v]", id, h.RTT, lo, hi)
		}
	}
	// 3 канала × 3 цели × (запрос + ответ).
	t.Logf("measure: probe traffic %.0f B per round for 3 links ≈ %.1f MB/day per link",
		perRound, perRound/3*43200/1e6)
}

func TestSilentBreakDetectionAndRecovery(t *testing.T) {
	b := start(t)
	events, unsub := b.bus.Subscribe(16, event.TopicLinkState)
	defer unsub()

	broke := time.Now()
	labCmd(t, "break", "isp1", "loss")
	t.Cleanup(func() { labCmd(t, "restore", "isp1") })
	down := b.wait(t, "isp1", model.LinkStateDown, 15*time.Second)
	detect := down.Sub(broke)
	t.Logf("measure: silent break detected in %v", detect.Round(100*time.Millisecond))
	if detect > 10*time.Second {
		t.Errorf("detection took %v, want ≤ 10 s", detect)
	}
	for _, id := range []model.LinkID{"isp2", "lte"} {
		if st, _ := b.mon.Status(id); st.Health.State != model.LinkStateUp {
			t.Errorf("%s affected by isp1 break: %s (%s)", id, st.Health.State, st.Health.Reason)
		}
	}

	restored := time.Now()
	labCmd(t, "restore", "isp1")
	up := b.wait(t, "isp1", model.LinkStateUp, 35*time.Second)
	rec := up.Sub(restored)
	t.Logf("measure: recovery confirmed in %v", rec.Round(100*time.Millisecond))
	// 10 удачных раундов по 2 с — 9 интервалов; раунд, начатый чуть раньше
	// восстановления, успевает получить ответы в пределах таймаута (1 с).
	if rec < 17*time.Second {
		t.Errorf("recovered in %v — earlier than recover_after allows", rec)
	}

	var sawDown, sawUp bool
	for len(events) > 0 {
		c := (<-events).Data.(event.LinkStateChange)
		if c.Link == "isp1" && c.To == model.LinkStateDown {
			sawDown = true
		}
		if c.Link == "isp1" && c.From == model.LinkStateDown && c.To == model.LinkStateUp {
			sawUp = true
		}
	}
	if !sawDown || !sawUp {
		t.Errorf("link.state events: down=%v up=%v", sawDown, sawUp)
	}
}

func TestCarrierCut(t *testing.T) {
	b := start(t)
	cut := time.Now()
	labCmd(t, "break", "isp2", "down")
	t.Cleanup(func() { labCmd(t, "restore", "isp2") })
	down := b.wait(t, "isp2", model.LinkStateDown, 15*time.Second)
	t.Logf("measure: carrier loss detected in %v", down.Sub(cut).Round(100*time.Millisecond))
	if down.Sub(cut) > 10*time.Second {
		t.Errorf("detection took %v, want ≤ 10 s", down.Sub(cut))
	}
	labCmd(t, "restore", "isp2")
	b.wait(t, "isp2", model.LinkStateUp, 35*time.Second)
}

func TestLossDegradesLink(t *testing.T) {
	b := start(t)
	// 10 % потерь на направление (~19 % на пробу туда-обратно).
	labCmd(t, "shape", "lte", "45", "10", "10", "60", "20")
	t.Cleanup(func() { labCmd(t, "shape", "lte", "45", "10", "0.5", "60", "20") })
	began := time.Now()
	b.wait(t, "lte", model.LinkStateDegraded, 40*time.Second)
	st, _ := b.mon.Status("lte")
	t.Logf("measure: degraded after %v: %s", time.Since(began).Round(100*time.Millisecond), st.Health.Reason)
	if !st.Health.State.Usable() {
		t.Error("degraded link must stay usable")
	}
}

func TestICMPFilteredFallsBackToTCP(t *testing.T) {
	b := start(t)
	nftIn(t, "tl-isp1", "table ip tl_blk { chain f { type filter hook forward priority 0; icmp type echo-request drop; }; }")
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "exec", "tl-isp1", "nft", "delete", "table", "ip", "tl_blk").Run()
	})
	time.Sleep(12 * time.Second) // больше fail_after раундов
	st, _ := b.mon.Status("isp1")
	if st.Health.State != model.LinkStateUp {
		t.Fatalf("isp1 with ICMP filtered: %s (%s), want up via TCP probe", st.Health.State, st.Health.Reason)
	}
	t.Logf("measure: TCP-probe rtt %v", st.Health.RTT.Round(100*time.Microsecond))
}

func TestWhitelistModeRestricted(t *testing.T) {
	b := start(t)
	// Оператор пропускает только «белый список» (203.0.113.3).
	nftIn(t, "tl-lte", "table ip tl_wl { chain f { type filter hook forward priority 0; ip daddr 203.0.113.0/24 ip daddr != 203.0.113.3 drop; }; }")
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "exec", "tl-lte", "nft", "delete", "table", "ip", "tl_wl").Run()
	})
	since := time.Now()
	b.wait(t, "lte", model.LinkStateRestricted, 15*time.Second)
	t.Logf("measure: whitelist mode detected in %v", time.Since(since).Round(100*time.Millisecond))
	if st, _ := b.mon.Status("lte"); st.Health.State.Usable() {
		t.Error("restricted link must not be usable")
	}
	if err := exec.Command("ip", "netns", "exec", "tl-lte", "nft", "delete", "table", "ip", "tl_wl").Run(); err != nil {
		t.Fatal(err)
	}
	b.wait(t, "lte", model.LinkStateUp, 35*time.Second)
}

func TestSpeedTestActiveAndPassive(t *testing.T) {
	b := start(t)
	labCmd(t, "shape", "isp1", "8", "1", "0", "50", "0")
	t.Cleanup(func() { labCmd(t, "shape", "isp1", "8", "1", "0", "0", "0") })
	th, err := b.mon.SpeedTest(context.Background(), "isp1")
	if err != nil {
		t.Fatal(err)
	}
	mbit := float64(th.DownBps) / 1e6
	t.Logf("measure: active speed test isp1 (shaped 50 Mbit/s): %.1f Mbit/s", mbit)
	if mbit < 35 || mbit > 60 {
		t.Errorf("speed test %.1f Mbit/s, want ≈ 50", mbit)
	}
	if _, err := b.mon.SpeedTest(context.Background(), "nope"); err == nil {
		t.Error("unknown link must fail")
	}
	time.Sleep(3 * time.Second) // раунд после замера учтёт пассивный пик
	st, _ := b.mon.Status("isp1")
	if float64(st.Health.Throughput.DownBps) < float64(th.DownBps)*0.9 {
		t.Errorf("status throughput %d below measured %d", st.Health.Throughput.DownBps, th.DownBps)
	}
}

func TestCaptivePortalRestricts(t *testing.T) {
	b := start(t)
	// «Провайдер» перехватывает весь HTTP и отдаёт страницу авторизации.
	nftIn(t, "tl-isp2", "table ip tl_portal { chain pre { type nat hook prerouting priority dstnat; tcp dport 80 dnat to 203.0.113.10:8080; }; }")
	del := func() {
		_ = exec.Command("ip", "netns", "exec", "tl-isp2", "nft", "delete", "table", "ip", "tl_portal").Run()
	}
	t.Cleanup(del)
	since := time.Now()
	b.wait(t, "isp2", model.LinkStateRestricted, 20*time.Second)
	st, _ := b.mon.Status("isp2")
	t.Logf("measure: captive portal detected in %v: %s", time.Since(since).Round(100*time.Millisecond), st.Health.Reason)
	if !strings.Contains(st.Health.Reason, "status 200") {
		t.Errorf("reason %q should name the substituted answer", st.Health.Reason)
	}
	if st.Health.RTT == 0 {
		t.Error("ICMP metrics must keep flowing while restricted by HTTP")
	}
	del()
	b.wait(t, "isp2", model.LinkStateUp, 15*time.Second)
}

func TestHTTPBlockedWhilePingWorks(t *testing.T) {
	b := start(t)
	nftIn(t, "tl-isp1", "table ip tl_nohttp { chain f { type filter hook forward priority 0; tcp dport 80 drop; }; }")
	del := func() {
		_ = exec.Command("ip", "netns", "exec", "tl-isp1", "nft", "delete", "table", "ip", "tl_nohttp").Run()
	}
	t.Cleanup(del)
	since := time.Now()
	b.wait(t, "isp1", model.LinkStateRestricted, 25*time.Second)
	t.Logf("measure: HTTP block detected in %v", time.Since(since).Round(100*time.Millisecond))
	del()
	b.wait(t, "isp1", model.LinkStateUp, 15*time.Second)
}

// TestSpeedTestFrozenTransferIsBlockNotSpeed — передача, застывшая после
// ~36 КБ (блок источника «после ~25 пакетов»; по байтам — на стенде veth
// склеивает пакеты до 64 КБ), должна дать ошибку «источник
// заблокирован», а не крошечную «скорость».
func TestSpeedTestFrozenTransferIsBlockNotSpeed(t *testing.T) {
	b := start(t)
	nftIn(t, "tl-isp1", "table ip tl_l425 { chain f { type filter hook forward priority 0; tcp sport 80 ct reply bytes > 36000 drop; }; }")
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "exec", "tl-isp1", "nft", "delete", "table", "ip", "tl_l425").Run()
	})
	began := time.Now()
	th, err := b.mon.SpeedTest(context.Background(), "isp1")
	t.Logf("measure: frozen source detected in %v: %v", time.Since(began).Round(100*time.Millisecond), err)
	if err == nil {
		t.Fatalf("frozen transfer reported as speed %d bit/s", th.DownBps)
	}
	if !errors.Is(err, ErrTransferFrozen) {
		t.Fatalf("want ErrTransferFrozen, got %v", err)
	}
}

// TestProbeSocketFollowsRecreatedInterface — интерфейс канала пересоздан (как
// переподключённый USB-модем): маршрут возвращает dataplane, а монитор
// открывает сокет проб заново — иначе ICMP-пробы, а с ними и распознавание
// «белых списков», молчали бы навсегда (канал держался бы на одной TCP-пробе).
func TestProbeSocketFollowsRecreatedInterface(t *testing.T) {
	b := start(t)
	labCmd(t, "recreate", "lte")
	t.Cleanup(func() { labCmd(t, "restore", "lte") })
	if err := b.dp.RepairRoutes(context.Background()); err != nil {
		t.Fatal(err)
	}
	// «Белые списки» видны только ICMP-пробам: restricted — значит, сокет живой.
	nftIn(t, "tl-lte", "table ip tl_wl { chain f { type filter hook forward priority 0; ip daddr 203.0.113.0/24 ip daddr != 203.0.113.3 drop; }; }")
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "exec", "tl-lte", "nft", "delete", "table", "ip", "tl_wl").Run()
	})
	since := time.Now()
	b.wait(t, "lte", model.LinkStateRestricted, 20*time.Second)
	t.Logf("measure: whitelist mode detected %v after interface recreation", time.Since(since).Round(100*time.Millisecond))
}

// Как в реальной сети (найдено со стенда по домашнему каналу): открытый DNS на
// порт 53 к сторонним серверам закрыт, DoT и DoH работают. С DNS на порт 53
// HTTP-проверка ложно делает канал restricted; с DoT/DoH канал остаётся up.
func TestHTTPCheckSurvivesBlockedPlainDNS(t *testing.T) {
	pem, err := os.ReadFile(labDoHCA)
	if err != nil {
		t.Fatalf("lab DoH CA: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatal("lab DoH CA: no certificates")
	}
	block := func(t *testing.T) {
		nftIn(t, "tl-isp1", "table ip tl_nodns { chain f { type filter hook forward priority 0; udp dport 53 drop; tcp dport 53 drop; }; }")
		t.Cleanup(func() {
			_ = exec.Command("ip", "netns", "exec", "tl-isp1", "nft", "delete", "table", "ip", "tl_nodns").Run()
		})
	}

	t.Run("plain DNS fails", func(t *testing.T) {
		b := start(t)
		block(t)
		since := time.Now()
		b.wait(t, "isp1", model.LinkStateRestricted, 25*time.Second)
		t.Logf("measure: blocked port 53 → restricted in %v", time.Since(since).Round(100*time.Millisecond))
		if st, _ := b.mon.Status("isp2"); st.Health.State != model.LinkStateUp {
			t.Errorf("isp2 affected: %s (%s)", st.Health.State, st.Health.Reason)
		}
	})
	for _, srv := range []DNSServer{
		{Proto: DNSOverHTTPS, Addr: netip.AddrPortFrom(labDNS, 443), URL: "https://203.0.113.53/dns-query"},
		{Proto: DNSOverTLS, Addr: netip.AddrPortFrom(labDNS, 853)},
	} {
		name := map[DNSProto]string{DNSOverHTTPS: "DoH", DNSOverTLS: "DoT"}[srv.Proto]
		t.Run(name+" keeps link up", func(t *testing.T) {
			b := startWith(t, func(o *Options) {
				o.HTTPCheck.DNS = []DNSServer{srv}
				o.HTTPCheck.RootCAs = roots
			})
			block(t)
			// 5 проверок по 4 с: при отказе хватило бы двух (fail_after 2).
			deadline := time.Now().Add(20 * time.Second)
			for time.Now().Before(deadline) {
				if st, _ := b.mon.Status("isp1"); st.Health.State != model.LinkStateUp {
					t.Fatalf("isp1 with %s: %s (%s)", name, st.Health.State, st.Health.Reason)
				}
				time.Sleep(500 * time.Millisecond)
			}
		})
	}
}
