package decision

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"tross/core/model"
)

// policies — как классы в configs/example.yaml.
func policies() map[model.TrafficClass]model.Policy {
	wired, lte := []model.LinkID{"isp1", "isp2"}, []model.LinkID{"lte"}
	return map[model.TrafficClass]model.Policy{
		model.ClassGaming:      {Selector: model.SelectLowestLatency, Stickiness: model.StickSession, StickyTTL: 2 * time.Hour, Links: wired, Fallback: lte, Method: model.MethodDirect, Priority: model.PriorityHigh},
		model.ClassVoIP:        {Selector: model.SelectLowestLatency, Stickiness: model.StickSession, StickyTTL: 2 * time.Hour, Links: wired, Fallback: lte, Method: model.MethodAuto, Priority: model.PriorityHigh},
		model.ClassStreaming:   {Selector: model.SelectBestThroughput, Stickiness: model.StickNone, Links: wired, Fallback: lte, Method: model.MethodAuto, AllowProxy: true, Priority: model.PriorityNormal},
		model.ClassBulk:        {Selector: model.SelectBalanced, Stickiness: model.StickNone, Links: wired, Method: model.MethodDirect, Priority: model.PriorityLow},
		model.ClassIPSensitive: {Selector: model.SelectOrdered, Stickiness: model.StickDestination, StickyTTL: 24 * time.Hour, Links: wired, Fallback: lte, Method: model.MethodAuto, Priority: model.PriorityNormal},
		model.ClassDefault:     {Selector: model.SelectBalanced, Stickiness: model.StickNone, Links: wired, Fallback: lte, Method: model.MethodAuto, AllowProxy: true, Priority: model.PriorityNormal},
	}
}

type bench struct {
	t     *testing.T
	e     *Engine
	now   time.Time
	links map[model.LinkID]*model.LinkStatus
}

func newBench(t *testing.T) *bench {
	b := &bench{t: t, now: time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC), links: map[model.LinkID]*model.LinkStatus{}}
	mk := func(id model.LinkID, kind model.LinkKind, prio int, rtt time.Duration, mbit uint64) {
		b.links[id] = &model.LinkStatus{
			Link:   model.Link{ID: id, Kind: kind, Priority: prio},
			Health: model.LinkHealth{LinkID: id, State: model.LinkStateUp, RTT: rtt, Throughput: model.Throughput{DownBps: mbit * 1_000_000}},
		}
	}
	mk("isp1", model.LinkKindWired, 1, 10*time.Millisecond, 500)
	mk("isp2", model.LinkKindWired, 2, 15*time.Millisecond, 300)
	mk("lte", model.LinkKindLTE, 3, 50*time.Millisecond, 60)
	e, err := NewEngine(policies(), func() time.Time { return b.now })
	if err != nil {
		t.Fatal(err)
	}
	b.e = e
	b.push()
	return b
}

func (b *bench) push() {
	var s []model.LinkStatus
	for _, id := range []model.LinkID{"isp1", "isp2", "lte"} {
		s = append(s, *b.links[id])
	}
	b.e.UpdateLinks(s)
}

func (b *bench) set(id model.LinkID, state model.LinkState, rtt time.Duration) {
	b.links[id].Health.State = state
	if rtt > 0 {
		b.links[id].Health.RTT = rtt
	}
	b.push()
}

func (b *bench) decide(src, dst, domain string, c model.Classification, rule *model.DomainRule) (model.Decision, error) {
	f := model.Flow{Proto: model.ProtoTCP, Src: netip.MustParseAddrPort(src), Dst: netip.MustParseAddrPort(dst), Domain: domain}
	return b.e.Decide(f, c, rule)
}

func (b *bench) link(src, dst, domain string, c model.Classification) model.LinkID {
	b.t.Helper()
	d, err := b.decide(src, dst, domain, c, nil)
	if err != nil {
		b.t.Fatalf("decide %s → %s (%s): %v", src, dst, c.Class, err)
	}
	return d.Link
}

func class(c model.TrafficClass) model.Classification { return model.Classification{Class: c} }

const pc, phone = "192.168.10.20:40000", "192.168.10.21:40000"

func TestGameSessionStaysOnItsLink(t *testing.T) {
	b := newBench(t)
	if l := b.link(pc, "5.5.5.5:27015", "", class(model.ClassGaming)); l != "isp1" {
		t.Fatalf("game start = %s, want lowest latency isp1", l)
	}
	// isp1 стал заметно хуже — новая сессия другого устройства идёт на isp2,
	// а соединения той же игровой сессии остаются на isp1.
	b.set("isp1", model.LinkStateUp, 40*time.Millisecond)
	if l := b.link(pc, "5.5.5.6:27016", "", class(model.ClassGaming)); l != "isp1" {
		t.Errorf("same session moved to %s", l)
	}
	if l := b.link(phone, "5.5.5.5:27015", "", class(model.ClassGaming)); l != "isp2" {
		t.Errorf("new session = %s, want faster isp2", l)
	}
	// Канал сессии упал — закрепление снимается.
	b.set("isp1", model.LinkStateDown, 0)
	if l := b.link(pc, "5.5.5.6:27016", "", class(model.ClassGaming)); l != "isp2" {
		t.Errorf("after isp1 down = %s, want isp2", l)
	}
}

// Новая сессия меняет канал, только если другой лучше и на 25 %, и на 10 мс;
// задержка — с джиттером (RTT + 2 × джиттер). Таблица согласована с
// пользователем.
func TestLatencySwitchRule(t *testing.T) {
	ms := func(v int) time.Duration { return time.Duration(v) * time.Millisecond }
	cases := []struct {
		name             string
		prevRTT, prevJit int
		nextRTT, nextJit int
		switched         bool
	}{
		{"10 → 9", 10, 0, 9, 0, false},
		{"10 → 4: both excellent", 10, 0, 4, 0, false},
		{"40 → 15", 40, 0, 15, 0, true},
		{"30 → 25", 30, 0, 25, 0, false},
		{"12 steady → 8 spiky", 12, 0, 8, 10, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := newBench(t)
			b.links["isp1"].Health.RTT, b.links["isp1"].Health.Jitter = ms(tc.prevRTT), ms(tc.prevJit)
			b.links["isp2"].Health.RTT, b.links["isp2"].Health.Jitter = ms(tc.prevRTT+20), 0
			b.push()
			if l := b.link(pc, "5.5.5.5:3478", "", class(model.ClassVoIP)); l != "isp1" {
				t.Fatalf("first = %s, want isp1", l)
			}
			b.links["isp2"].Health.RTT, b.links["isp2"].Health.Jitter = ms(tc.nextRTT), ms(tc.nextJit)
			b.push()
			l := b.link(phone, "5.5.5.5:3478", "", class(model.ClassVoIP))
			if got := l == "isp2"; got != tc.switched {
				t.Errorf("new session on %s; switched = %v, want %v", l, got, tc.switched)
			}
		})
	}
}

func TestBulkNeverLTEAndNeverProxy(t *testing.T) {
	b := newBench(t)
	proxy := &model.DomainRule{Pattern: "tracker.example", Match: model.MatchSuffix, Layer: model.LayerManual, Method: model.MethodProxy, ProxyID: "nl1"}
	d, err := b.decide(pc, "5.5.5.5:51413", "tracker.example", class(model.ClassBulk), proxy)
	if err != nil || d.Method != model.MethodDirect || d.Link == "lte" {
		t.Fatalf("bulk with proxy rule = %+v, %v; want direct on a wired link", d, err)
	}
	b.set("isp1", model.LinkStateDown, 0)
	b.set("isp2", model.LinkStateDown, 0)
	if d, err := b.decide(pc, "5.5.5.5:51413", "", class(model.ClassBulk), nil); !errors.Is(err, ErrNoUsableLink) {
		t.Fatalf("bulk with both wired down = %+v, %v; want ErrNoUsableLink (never LTE)", d, err)
	}
}

func TestVideoUsesLTEOnlyWhenWiredDown(t *testing.T) {
	b := newBench(t)
	if l := b.link(pc, "8.8.8.8:443", "rr1.googlevideo.com", class(model.ClassStreaming)); l != "isp1" {
		t.Fatalf("video = %s, want best throughput isp1", l)
	}
	b.set("isp1", model.LinkStateDown, 0)
	if l := b.link(pc, "8.8.8.8:443", "rr1.googlevideo.com", class(model.ClassStreaming)); l != "isp2" {
		t.Fatalf("video with isp1 down = %s, want isp2", l)
	}
	b.set("isp2", model.LinkStateDown, 0)
	d, err := b.decide(pc, "8.8.8.8:443", "rr1.googlevideo.com", class(model.ClassStreaming), nil)
	if err != nil || d.Link != "lte" || !strings.Contains(d.Reason, "fallback") {
		t.Fatalf("video with both wired down = %+v, %v; want lte fallback", d, err)
	}
	b.set("isp2", model.LinkStateUp, 0)
	if l := b.link(pc, "8.8.8.8:443", "rr1.googlevideo.com", class(model.ClassStreaming)); l != "isp2" {
		t.Errorf("video after isp2 back = %s, want off LTE", l)
	}
}

func TestServicePinKeepsYouTubeOnOneLink(t *testing.T) {
	b := newBench(t)
	yt := model.Classification{Class: model.ClassDefault, Service: "youtube", Part: "video", PinService: true}
	// Класс default балансирует по хешу назначения: без закрепления разные
	// узлы видео разошлись бы по каналам.
	first := b.link(pc, "8.8.8.8:443", "www.youtube.com", yt)
	for i := range 50 {
		dst := fmt.Sprintf("173.194.%d.%d:443", i, i+1)
		if l := b.link(pc, dst, fmt.Sprintf("rr%d.googlevideo.com", i), yt); l != first {
			t.Fatalf("youtube flow %d went to %s, page on %s", i, l, first)
		}
	}
	// Падение канала снимает закрепление.
	b.set(first, model.LinkStateDown, 0)
	if l := b.link(pc, "8.8.8.8:443", "www.youtube.com", yt); l == first {
		t.Errorf("pin survived link down")
	}
}

func TestBalancedIsDeterministicAndWeighted(t *testing.T) {
	b := newBench(t)
	counts := map[model.LinkID]int{}
	for i := range 2000 {
		dst := fmt.Sprintf("%d.%d.%d.%d:443", 20+i%200, i%251, i%241, i%239)
		l := b.link(pc, dst, "", class(model.ClassDefault))
		if again := b.link(pc, dst, "", class(model.ClassDefault)); again != l {
			t.Fatalf("same destination split: %s then %s", l, again)
		}
		counts[l]++
	}
	// Веса по скорости 500:300 → ~62 % / 38 %; LTE — только запасной.
	share := float64(counts["isp1"]) / 2000
	if share < 0.55 || share > 0.70 || counts["lte"] != 0 {
		t.Errorf("balanced split = %v (isp1 %.2f), want ~0.62 and no LTE", counts, share)
	}
}

func TestDestinationPinExpires(t *testing.T) {
	b := newBench(t)
	bank := class(model.ClassIPSensitive)
	if l := b.link(pc, "1.2.3.4:443", "online.bank.example", bank); l != "isp1" {
		t.Fatalf("ordered = %s, want isp1", l)
	}
	// isp1 ухудшился, но жив — банк остаётся на нём, пока действует закрепление.
	b.set("isp1", model.LinkStateDegraded, 0)
	b.links["isp1"].Link.Priority, b.links["isp2"].Link.Priority = 2, 1
	b.push()
	b.now = b.now.Add(23 * time.Hour)
	if l := b.link(pc, "1.2.3.5:443", "online.bank.example", bank); l != "isp1" {
		t.Errorf("pinned bank moved to %s before TTL", l)
	}
	// Закрепление продлевается при использовании; без обращений — истекает.
	b.now = b.now.Add(25 * time.Hour)
	b.e.Prune()
	d, _ := b.decide(pc, "1.2.3.5:443", "online.bank.example", bank, nil)
	if d.Sticky && strings.Contains(d.Reason, "pinned") {
		t.Errorf("expired pin still used: %+v", d)
	}
}

func TestMethodAndRuleLink(t *testing.T) {
	b := newBench(t)
	dpi := &model.DomainRule{Pattern: "blocked.example", Match: model.MatchSuffix, Layer: model.LayerLearned, Method: model.MethodDirectDPI, Link: "isp2"}
	d, err := b.decide(pc, "5.5.5.5:443", "blocked.example", class(model.ClassDefault), dpi)
	if err != nil || d.Method != model.MethodDirectDPI || d.Link != "isp2" {
		t.Fatalf("learned dpi rule = %+v, %v; want direct_dpi on isp2", d, err)
	}
	// Правило не может вывести соединение за пределы политики класса.
	toLTE := &model.DomainRule{Pattern: "x.example", Match: model.MatchSuffix, Layer: model.LayerManual, Link: "lte"}
	if d, _ := b.decide(pc, "5.5.5.5:443", "x.example", class(model.ClassBulk), toLTE); d.Link == "lte" {
		t.Errorf("domain rule pushed bulk onto LTE")
	}
	// Игры — только напрямую, что бы ни говорило правило.
	proxy := &model.DomainRule{Pattern: "game.example", Match: model.MatchSuffix, Layer: model.LayerManual, Method: model.MethodProxy, ProxyID: "nl1"}
	if d, _ := b.decide(pc, "5.5.5.5:443", "game.example", class(model.ClassGaming), proxy); d.Method != model.MethodDirect {
		t.Errorf("gaming method = %s, want direct", d.Method)
	}
	// Неизвестный класс — по политике default.
	if d, err := b.decide(pc, "5.5.5.5:443", "", class("custom"), nil); err != nil || !strings.Contains(d.Reason, "default used") {
		t.Errorf("unknown class = %+v, %v", d, err)
	}
}

func TestPoliciesValidated(t *testing.T) {
	p := policies()
	delete(p, model.ClassDefault)
	if _, err := NewEngine(p, nil); err == nil {
		t.Error("no default policy accepted")
	}
	p = policies()
	p[model.ClassGaming] = model.Policy{Selector: "fastest"}
	if _, err := NewEngine(p, nil); err == nil {
		t.Error("invalid policy accepted")
	}
}

func TestBroadcastPicksBestUploadPerPlatform(t *testing.T) {
	b := newBench(t)
	b.links["isp1"].Health.Throughput.UpBps = 20_000_000
	b.links["isp2"].Health.Throughput.UpBps = 50_000_000
	b.links["lte"].Health.Throughput.UpBps = 90_000_000
	b.push()
	p := policies()
	p[model.ClassBroadcast] = model.Policy{Selector: model.SelectBestUpload, Stickiness: model.StickDestination, StickyTTL: 12 * time.Hour,
		Links: []model.LinkID{"isp1", "isp2"}, Method: model.MethodAuto, AllowProxy: true, Priority: model.PriorityNormal}
	if err := b.e.SetPolicies(p); err != nil {
		t.Fatal(err)
	}
	live := class(model.ClassBroadcast)
	if l := b.link(pc, "8.8.8.8:443", "a.rtmp.youtube.com", live); l != "isp2" {
		t.Fatalf("youtube ingest = %s, want best upload isp2 (LTE is never allowed)", l)
	}
	// Небольшой перевес (60 против 50) — не повод менять выбор (гистерезис).
	b.links["isp1"].Health.Throughput.UpBps = 60_000_000
	b.push()
	if l := b.link(pc, "1.1.1.1:443", "live-fra.contribute.live-video.net", live); l != "isp2" {
		t.Errorf("twitch ingest with isp1 60 vs isp2 50 = %s, want isp2 kept", l)
	}
	// Закрепление по назначению: другая платформа выбирается заново, а тот
	// же адрес приёма после переподключения OBS — на тот же канал.
	b.links["isp1"].Health.Throughput.UpBps = 80_000_000
	b.push()
	if l := b.link(pc, "1.1.1.2:443", "live-ams.contribute.live-video.net", live); l != "isp1" {
		t.Errorf("twitch ingest = %s, want isp1 with clearly more upload now", l)
	}
	if l := b.link(pc, "8.8.8.8:443", "a.rtmp.youtube.com", live); l != "isp2" {
		t.Errorf("youtube reconnect moved to %s", l)
	}
}

func TestPlanFollowsLinksWithHysteresis(t *testing.T) {
	b := newBench(t)
	plan := func(c model.TrafficClass) ClassPlan {
		for _, p := range b.e.Plan() {
			if p.Class == c {
				return p
			}
		}
		t.Fatalf("no plan for %s", c)
		return ClassPlan{}
	}
	g := plan(model.ClassGaming)
	if len(g.Shares) != 1 || g.Shares[0].Link != "isp1" || g.Pin != model.StickSession || !slices.Equal(g.PinLinks, []model.LinkID{"isp1", "isp2"}) {
		t.Fatalf("gaming plan = %+v", g)
	}
	// Небольшое улучшение isp2 — план не меняется (то же правило, что у Decide).
	b.set("isp2", model.LinkStateUp, 9*time.Millisecond)
	if g2 := plan(model.ClassGaming); !g2.Equal(g) {
		t.Errorf("plan changed on a minor RTT gain: %+v", g2)
	}
	// Оба проводных упали: закрепления действуют только на LTE; у bulk — ничего.
	b.set("isp1", model.LinkStateDown, 0)
	b.set("isp2", model.LinkStateDown, 0)
	if g3 := plan(model.ClassGaming); !slices.Equal(g3.PinLinks, []model.LinkID{"lte"}) || g3.Shares[0].Link != "lte" {
		t.Errorf("gaming plan with wired down = %+v", g3)
	}
	if bl := plan(model.ClassBulk); len(bl.Shares) != 0 || len(bl.PinLinks) != 0 {
		t.Errorf("bulk plan with wired down = %+v, want nothing (never LTE)", bl)
	}
	// Вернулся проводной — закрепления на LTE больше не действуют.
	b.set("isp2", model.LinkStateUp, 0)
	if g4 := plan(model.ClassGaming); slices.Contains(g4.PinLinks, "lte") {
		t.Errorf("lte pins still honored after isp2 back: %+v", g4)
	}
}

func TestExplainHasNoSideEffects(t *testing.T) {
	b := newBench(t)
	f := model.Flow{Proto: model.ProtoUDP, Src: netip.MustParseAddrPort(pc), Dst: netip.MustParseAddrPort("5.5.5.5:27015")}
	game := class(model.ClassGaming)
	// Объяснение не закрепляет сессию.
	d, err := b.e.Explain(f, game, nil)
	if err != nil || d.Link != "isp1" || !d.Sticky {
		t.Fatalf("explain = %+v, %v", d, err)
	}
	if len(b.e.pins) != 0 {
		t.Fatalf("Explain created pins: %v", b.e.pins)
	}
	// Закреплённую сессию объясняет как закреплённую, но срок не продлевает.
	if _, err := b.e.Decide(f, game, nil); err != nil {
		t.Fatal(err)
	}
	before := b.e.pins
	exp := map[pinKey]pin{}
	for k, v := range before {
		exp[k] = v
	}
	b.now = b.now.Add(time.Hour)
	b.set("isp2", model.LinkStateUp, 2*time.Millisecond)
	d, _ = b.e.Explain(f, game, nil)
	if d.Link != "isp1" || !strings.Contains(d.Reason, "pinned") {
		t.Errorf("explain of pinned session = %+v", d)
	}
	for k, v := range b.e.pins {
		if exp[k] != v {
			t.Errorf("Explain changed pin %v: %v → %v", k, exp[k], v)
		}
	}
}
