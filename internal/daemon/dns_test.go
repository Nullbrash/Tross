package daemon

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"tross/core/decision"
	"tross/core/event"
	corelists "tross/core/lists"
	"tross/core/model"
	"tross/internal/dataplane"
)

func TestWeightedChoice(t *testing.T) {
	shares := []decision.LinkShare{{Link: "isp1", Weight: 3}, {Link: "isp2", Weight: 1}}
	first := weightedChoice("example.com", shares)
	count := map[model.LinkID]int{}
	for i := range 4000 {
		count[weightedChoice(fmt.Sprintf("site%d.com", i), shares)]++
	}
	if c := count["isp1"]; c < 2800 || c > 3200 {
		t.Errorf("weights 3:1 → %v", count)
	}
	if weightedChoice("example.com", shares) != first {
		t.Error("same key must give the same link")
	}
	// Ушёл isp2 — переезжают только его сайты.
	three := append(shares, decision.LinkShare{Link: "lte", Weight: 1})
	moved := 0
	for i := range 1000 {
		k := fmt.Sprintf("site%d.com", i)
		if a, b := weightedChoice(k, three), weightedChoice(k, shares); a != b && a != "lte" {
			moved++
		}
	}
	if moved != 0 {
		t.Errorf("%d sites moved between links that stayed", moved)
	}
}

func dnsRouteBench(t *testing.T, pins []dataplane.Pin) *dnsService {
	t.Helper()
	cfg := exampleCfg(t)
	cat, err := serviceCatalog(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cls, err := newClassifier(cfg, cat, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	dp := dataplane.NewFake(slog.New(slog.NewTextHandler(io.Discard, nil)))
	dp.SetObserved(nil, pins)
	two := []decision.LinkShare{{Link: "isp1", Weight: 1}, {Link: "isp2", Weight: 1}}
	plan := []decision.ClassPlan{
		{Class: model.ClassStreaming, Shares: two},
		{Class: model.ClassDefault, Shares: two},
		{Class: model.ClassGaming, Shares: []decision.LinkShare{{Link: "isp1", Weight: 1}}},
	}
	return &dnsService{dp: dp, cls: cls, plan: func() []decision.ClassPlan { return plan },
		linkIdx: map[model.LinkID]int{"isp1": 0, "isp2": 1, "lte": 2}}
}

var dev = netip.MustParseAddr("192.168.10.30")

func TestRouteByDomain(t *testing.T) {
	s := dnsRouteBench(t, nil)
	// Все домены YouTube (закрепление сервиса) — один канал.
	first, pin, ok := s.route("www.youtube.com", dev)
	if !ok || pin != dataplane.DomainLinkSet(s.linkIdx[first]) {
		t.Fatalf("youtube: %s %s %v", first, pin, ok)
	}
	for _, d := range []string{"i.ytimg.com", "rr3---sn-abc.googlevideo.com", "youtube.com"} {
		if l, _, _ := s.route(d, dev); l != first {
			t.Errorf("%s → %s, want %s with the rest of youtube", d, l, first)
		}
	}
	// Имена одного сайта — один канал.
	a, _, _ := s.route("api.example.org", dev)
	b, _, _ := s.route("cdn.example.org", dev)
	if a != b {
		t.Errorf("one site, two links: %s %s", a, b)
	}
	// У класса один канал — выбирать нечего, множество не нужно.
	s2 := dnsRouteBench(t, nil)
	s2.plan = func() []decision.ClassPlan {
		return []decision.ClassPlan{{Class: model.ClassDefault, Shares: []decision.LinkShare{{Link: "isp2", Weight: 1}}}}
	}
	if l, pin, _ := s2.route("example.org", dev); l != "isp2" || pin != "" {
		t.Errorf("single share: %s %q", l, pin)
	}
	// Плана нет вовсе — DNS некуда.
	s2.plan = func() []decision.ClassPlan { return nil }
	if _, _, ok := s2.route("example.org", dev); ok {
		t.Error("no plan must give no route")
	}
}

// Закреплённое устройство спрашивает DNS через свой канал, а множество
// «домен → канал» — по-прежнему по сайту (одно на всех устройств).
func TestRouteFollowsDevicePin(t *testing.T) {
	s := dnsRouteBench(t, nil)
	domainLink, _, _ := s.route("www.youtube.com", dev)
	other := model.LinkID("isp1")
	if domainLink == "isp1" {
		other = "isp2"
	}
	s = dnsRouteBench(t, []dataplane.Pin{{Service: "youtube", Device: dev, Link: other}})
	q, pin, _ := s.route("www.youtube.com", dev)
	if q != other || pin != dataplane.DomainLinkSet(s.linkIdx[domainLink]) {
		t.Errorf("pinned device: query %s (want %s), pin set %s", q, other, pin)
	}
	if q, _, _ := s.route("www.youtube.com", netip.MustParseAddr("192.168.10.31")); q != domainLink {
		t.Errorf("another device is not pinned: %s", q)
	}
}

// Перехват — на резолвер, когда он слушает; при остановке — обратно на
// запасной.
func TestDNSServiceSwitchesInterception(t *testing.T) {
	cfg := exampleCfg(t)
	l, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg.DNS.Listen = []string{l.LocalAddr().String()}
	l.Close()
	cfg.DNS.Watchdog.Interval = 50 * time.Millisecond
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	dp := dataplane.NewFake(log)
	cat, _ := serviceCatalog(cfg)
	cls, _ := newClassifier(cfg, cat, nil, nil)
	spec, err := dataplaneSpec(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := newDNSService(cfg, log, dp, event.NewBus(), spec, cat, cls, corelists.NewRules(), func() []decision.ClassPlan { return nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.run(ctx); close(done) }()
	deadline := time.Now().Add(3 * time.Second)
	for !slices.Contains(dp.Ops(), "set-dns [true]") {
		if time.Now().After(deadline) {
			t.Fatalf("interception never switched to the resolver: %v", dp.Ops())
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond) // несколько самопроверок — без лишних переключений
	cancel()
	<-done
	var dns []string
	for _, op := range dp.Ops() {
		if strings.HasPrefix(op, "set-dns") {
			dns = append(dns, op)
		}
	}
	if !slices.Equal(dns, []string{"set-dns [true]", "set-dns [false]"}) {
		t.Errorf("switches %v — want on once, off at stop", dns)
	}
}

// slowPins — ядро, отвечающее о закреплениях медленно (как nft на мини-ПК).
type slowPins struct {
	dataplane.Dataplane
	delay time.Duration
}

func (s slowPins) Pins(ctx context.Context) ([]dataplane.Pin, error) {
	time.Sleep(s.delay)
	return s.Dataplane.Pins(ctx)
}

// Устаревшие закрепления обновляются в фоне: ответ не ждёт ядро.
func TestDevicePinsRefreshInBackground(t *testing.T) {
	s := dnsRouteBench(t, nil)
	fake := s.dp.(*dataplane.Fake)
	s.dp = slowPins{Dataplane: fake, delay: 300 * time.Millisecond}
	domainLink, _, _ := s.route("www.youtube.com", dev)
	other := model.LinkID("isp1")
	if domainLink == "isp1" {
		other = "isp2"
	}
	fake.SetObserved(nil, []dataplane.Pin{{Service: "youtube", Device: dev, Link: other}})
	s.mu.Lock()
	s.pinsAt = time.Now().Add(-time.Hour)
	s.mu.Unlock()
	start := time.Now()
	if q, _, _ := s.route("www.youtube.com", dev); q != domainLink {
		t.Errorf("stale pins expected right away, got %s", q)
	}
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Errorf("route waited %v for the kernel", d)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if q, _, _ := s.route("www.youtube.com", dev); q == other {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("background refresh never delivered the new pin")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
