//go:build linux && integration

package dataplane

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ti-mo/conntrack"

	"tross/core/decision"
	"tross/core/model"
	"tross/core/profile"
)

// classStand — классы стенда: игры (правило — UDP 9001–9010), звонки
// (STUN из каталога), видео (YouTube из каталога), загрузки (правило — TCP 88,
// только проводные), default.
func classStand(t *testing.T) Spec {
	t.Helper()
	cat, err := profile.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	all := []model.LinkID{"isp1", "isp2", "lte"}
	classes := []model.TrafficClass{model.ClassGaming, model.ClassVoIP, model.ClassStreaming, model.ClassBulk, model.ClassDefault}
	pol := map[model.TrafficClass]ClassPolicy{
		model.ClassGaming:    {Pin: model.StickSession, PinTTL: time.Hour, Allowed: all},
		model.ClassVoIP:      {Pin: model.StickNone, Allowed: all},
		model.ClassStreaming: {Pin: model.StickNone, Allowed: all},
		model.ClassBulk:      {Pin: model.StickNone, Allowed: []model.LinkID{"isp1", "isp2"}},
		model.ClassDefault:   {Pin: model.StickNone, Allowed: all},
	}
	user := []UserRule{
		{Name: "lab-game", Class: model.ClassGaming, Match: profile.Match{Proto: model.ProtoUDP, Ports: []profile.PortRange{{From: 9001, To: 9010}}}},
		{Name: "lab-bulk", Class: model.ClassBulk, Match: profile.Match{Proto: model.ProtoTCP, Ports: []profile.PortRange{{From: 88, To: 88}}}},
	}
	spec := standSpec()
	spec.Classify = CompileClassify(classes, pol, user, cat)
	return spec
}

func one(id model.LinkID) []decision.LinkShare { return []decision.LinkShare{{Link: id, Weight: 1}} }

func setPlan(t *testing.T, s *System, plan ...decision.ClassPlan) {
	t.Helper()
	if err := s.SetPlan(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
}

func inClientBash(t *testing.T, script string) (string, error) {
	t.Helper()
	return run(t, "ip", "netns", "exec", "tl-client", "bash", "-c", script)
}

// udp шлёт один датаграм из клиента (новый порт источника — новое соединение).
func udp(t *testing.T, port, payload string) {
	t.Helper()
	if out, err := inClientBash(t, "printf '"+payload+"' > /dev/udp/"+srv+"/"+port); err != nil {
		t.Fatalf("udp to %s: %v %s", port, err, out)
	}
	time.Sleep(200 * time.Millisecond)
}

// client — адрес клиента стенда: учитываются только его соединения (сам
// tl-tross и прошлые тесты оставляют в conntrack свои).
var client = netip.MustParseAddr("192.168.77.10")

// marks — метки соединений клиента к srv:port. Номер conntrack не растёт по
// порядку, поэтому каждая проверка — на своём порту назначения.
func marks(t *testing.T, proto uint8, port uint16) []uint32 {
	t.Helper()
	c, err := conntrack.Dial(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	flows, err := c.Dump(nil)
	if err != nil {
		t.Fatal(err)
	}
	dst := netip.MustParseAddr(srv)
	var out []uint32
	for _, f := range flows {
		o := f.TupleOrig
		if o.IP.SourceAddress == client && o.IP.DestinationAddress == dst && o.Proto.Protocol == proto && o.Proto.DestinationPort == port {
			out = append(out, f.Mark)
		}
	}
	return out
}

// onlyMark — у всех соединений клиента к порту одна метка, и она равна want.
func onlyMark(t *testing.T, proto uint8, port uint16, want uint32, what string) {
	t.Helper()
	m := marks(t, proto, port)
	if len(m) == 0 {
		t.Errorf("%s: no connection to %s:%d", what, srv, port)
	}
	for _, x := range m {
		if x != want {
			t.Errorf("%s: mark %#x, want %#x (all: %#x)", what, x, want, m)
			return
		}
	}
}

const (
	protoTCP = 6
	protoUDP = 17
	// STUN Binding Request: тип 1, длина 0, magic cookie, 12 байт ID.
	stunRequest = `\x00\x01\x00\x00\x21\x12\xa4\x42abcdefghijkl`
)

func TestClassChainsRouteByClass(t *testing.T) {
	s := newSystem(t)
	spec := classStand(t)
	if err := s.Setup(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	c := spec.Classify
	setPlan(t, s,
		decision.ClassPlan{Class: model.ClassDefault, Shares: one("isp1"), PinLinks: []model.LinkID{"isp1"}},
		decision.ClassPlan{Class: model.ClassGaming, Shares: one("isp2"), PinLinks: []model.LinkID{"isp2"}},
		decision.ClassPlan{Class: model.ClassVoIP, Shares: one("lte"), PinLinks: []model.LinkID{"lte"}},
	)
	udp(t, "9002", "game")
	onlyMark(t, protoUDP, 9002, 0x200|c.classID(model.ClassGaming), "game UDP (rule)")
	// Порт без правил: STUN в первом пакете — звонок, без него — default.
	udp(t, "9100", stunRequest)
	onlyMark(t, protoUDP, 9100, 0x300|c.classID(model.ClassVoIP), "STUN first packet")
	udp(t, "9101", "plain")
	onlyMark(t, protoUDP, 9101, 0x100|c.classID(model.ClassDefault), "plain UDP")
	if got, err := fetch(t, 100_000); err != nil || got != 100_000 {
		t.Fatalf("default TCP fetch: %d, %v", got, err)
	}
}

func TestSessionPinSurvivesPlanChange(t *testing.T) {
	s := newSystem(t)
	spec := classStand(t)
	if err := s.Setup(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	gid := spec.Classify.classID(model.ClassGaming)
	game := func(shares model.LinkID, pins ...model.LinkID) {
		setPlan(t, s, decision.ClassPlan{Class: model.ClassGaming, Shares: one(shares), PinLinks: pins})
	}
	game("isp1", "isp1", "isp2")
	udp(t, "9003", "start")
	// Новые сессии — на isp2, но у этого устройства сессия уже идёт: остаётся на isp1.
	game("isp2", "isp1", "isp2")
	udp(t, "9004", "more")
	onlyMark(t, protoUDP, 9004, 0x100|gid, "pinned session after plan change")
	// isp1 больше не годится — закрепление очищено, сессия идёт по плану.
	game("isp2", "isp2")
	udp(t, "9005", "after")
	onlyMark(t, protoUDP, 9005, 0x200|gid, "session after isp1 left pins")
}

func TestBulkRejectedWithoutAllowedLink(t *testing.T) {
	s := newSystem(t)
	if err := s.Setup(context.Background(), classStand(t)); err != nil {
		t.Fatal(err)
	}
	setPlan(t, s, decision.ClassPlan{Class: model.ClassBulk}) // проводные недоступны
	start := time.Now()
	if out, err := inClientBash(t, "timeout 4 bash -c '</dev/tcp/"+srv+"/88'"); err == nil {
		t.Fatalf("bulk connected without an allowed link: %s", out)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("bulk refusal took %v — rejected connections must fail fast", d)
	}
	t.Logf("measure: bulk without allowed link refused in %v", time.Since(start).Round(10*time.Millisecond))
	setPlan(t, s, decision.ClassPlan{Class: model.ClassBulk, Shares: one("isp2"), PinLinks: []model.LinkID{"isp2"}})
	if out, err := inClientBash(t, "timeout 4 bash -c '</dev/tcp/"+srv+"/88'"); err != nil {
		t.Fatalf("bulk with isp2 allowed: %v %s", err, out)
	}
}

func TestDomainSetSelectsServiceChain(t *testing.T) {
	s := newSystem(t)
	spec := classStand(t)
	if err := s.Setup(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	var set SetName
	for _, n := range spec.Classify.domainSets() {
		if strings.HasPrefix(string(n), "tross_dp_youtube_video") {
			set = n
		}
	}
	if set == "" {
		t.Fatal("no youtube domain set compiled")
	}
	setPlan(t, s,
		decision.ClassPlan{Class: model.ClassDefault, Shares: one("isp1"), PinLinks: []model.LinkID{"isp1"}},
		decision.ClassPlan{Class: model.ClassStreaming, Shares: one("isp2"), PinLinks: []model.LinkID{"isp2"}},
	)
	// Резолвер (этап 4) положит адреса YouTube в множество — здесь вручную.
	if err := s.AddToSet(context.Background(), set, netip.MustParseAddr(srv), time.Minute); err != nil {
		t.Fatal(err)
	}
	// Портал стенда (HTTP на 8080) — как адрес YouTube.
	get := func() {
		t.Helper()
		if out, err := inClient(t, "wget -q -T 5 --tries=1 -O - http://"+srv+":8080/ | wc -c"); err != nil {
			t.Fatalf("wget portal: %v %s", err, out)
		}
	}
	get()
	want := 0x200 | spec.Classify.classID(model.ClassStreaming)
	onlyMark(t, protoTCP, 8080, want, "youtube address")
	// Сервис закреплён: план видео сменился, а устройство остаётся на своём канале.
	setPlan(t, s, decision.ClassPlan{Class: model.ClassStreaming, Shares: one("isp1"), PinLinks: []model.LinkID{"isp1", "isp2"}})
	get()
	onlyMark(t, protoTCP, 8080, want, "service pin after plan change")
}

func TestBitTorrentOnForbiddenLinkIsCutAndLearned(t *testing.T) {
	s := newSystem(t)
	spec := classStand(t)
	if err := s.Setup(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	// Всё прочее идёт через LTE, загрузкам он запрещён.
	setPlan(t, s,
		decision.ClassPlan{Class: model.ClassDefault, Shares: one("lte"), PinLinks: []model.LinkID{"lte"}},
		decision.ClassPlan{Class: model.ClassBulk, Shares: one("isp1"), PinLinks: []model.LinkID{"isp1"}},
	)
	// iperf3 стенда (5201) — не торрентовый порт: соединение идёт как default
	// через LTE, пока в первых пакетах не окажется рукопожатие BitTorrent.
	out, err := inClientBash(t, `exec 3<>/dev/tcp/`+srv+`/5201 && printf '\x13BitTorrent protocol' >&3 && sleep 1 && printf 'x' >&3 && sleep 1 && printf 'y' >&3 && echo still-open`)
	if err == nil && strings.Contains(out, "still-open") {
		t.Fatalf("BitTorrent handshake over LTE was not cut: %q", out)
	}
	list, _ := run(t, "nft", "list", "set", "inet", "tross", string(setBTPeers))
	if !strings.Contains(list, srv+" . 5201") {
		t.Fatalf("peer not learned:\n%s", list)
	}
	// Следующее соединение к этому пиру — сразу bulk через isp1.
	if out, err := inClientBash(t, "timeout 4 bash -c '</dev/tcp/"+srv+"/5201'"); err != nil {
		t.Fatalf("connect after learning: %v %s", err, out)
	}
	want := 0x100 | spec.Classify.classID(model.ClassBulk)
	found := false
	for _, m := range marks(t, protoTCP, 5201) {
		found = found || m == want
	}
	if !found {
		t.Errorf("no connection to the learned peer with isp1 + bulk: %#x", marks(t, protoTCP, 5201))
	}
}

// Connections и Pins читают то, что ядро сделало на самом деле: класс и
// канал — из меток conntrack, закрепления — из множеств nft (формат JSON
// nft проверяется здесь, в юнит-тесте он записан вручную).
func TestConnectionsAndPinsFromKernel(t *testing.T) {
	s := newSystem(t)
	spec := classStand(t)
	ctx := context.Background()
	if err := s.Setup(ctx, spec); err != nil {
		t.Fatal(err)
	}
	setPlan(t, s,
		decision.ClassPlan{Class: model.ClassDefault, Shares: one("isp1"), PinLinks: []model.LinkID{"isp1"}},
		decision.ClassPlan{Class: model.ClassGaming, Shares: one("isp2"), PinLinks: []model.LinkID{"isp1", "isp2"}},
		decision.ClassPlan{Class: model.ClassStreaming, Shares: one("isp1"), PinLinks: []model.LinkID{"isp1"}},
	)
	udp(t, "9006", "game")
	for _, n := range spec.Classify.domainSets() {
		if strings.HasPrefix(string(n), "tross_dp_youtube_video") {
			if err := s.AddToSet(ctx, n, netip.MustParseAddr(srv), time.Minute); err != nil {
				t.Fatal(err)
			}
		}
	}
	if out, err := inClient(t, "wget -q -T 5 --tries=1 -O - http://"+srv+":8080/ | wc -c"); err != nil {
		t.Fatalf("wget portal: %v %s", err, out)
	}

	conns, err := s.Connections(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var game, video *Connection
	for i, c := range conns {
		if c.Src.Addr() != client {
			continue
		}
		switch {
		case c.Proto == "udp" && c.Dst.Port() == 9006:
			game = &conns[i]
		case c.Proto == "tcp" && c.Dst.Port() == 8080 && c.Class == model.ClassStreaming:
			video = &conns[i]
		}
	}
	if game == nil || game.Link != "isp2" || game.Class != model.ClassGaming || game.Timeout <= 0 {
		t.Errorf("game connection = %+v", game)
	}
	if video == nil || video.Link != "isp1" || video.State == "" {
		t.Errorf("video connection = %+v", video)
	}
	t.Logf("measure: %d marked connections, game %+v, video %+v", len(conns), game, video)

	pins, err := s.Pins(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var sess, svc bool
	for _, p := range pins {
		if p.Device != client || p.Expires <= 0 || p.Expires > time.Hour {
			continue
		}
		sess = sess || p.Class == model.ClassGaming && p.Service == "" && p.Link == "isp2"
		svc = svc || p.Service == "youtube" && p.Link == "isp1"
	}
	if !sess || !svc {
		t.Errorf("pins (session %v, service %v): %+v", sess, svc, pins)
	}
}
