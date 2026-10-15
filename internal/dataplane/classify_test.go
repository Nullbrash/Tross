package dataplane

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"tross/core/decision"
	"tross/core/model"
	"tross/core/profile"
)

// classifySpec — классы и политики как в configs/example.yaml.
func classifySpec(t *testing.T) (Spec, Classify) {
	t.Helper()
	cat, err := profile.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	wired := []model.LinkID{"isp1", "isp2"}
	all := []model.LinkID{"isp1", "isp2", "lte"}
	classes := []model.TrafficClass{model.ClassGaming, model.ClassVoIP, model.ClassStreaming, model.ClassBulk, model.ClassIPSensitive, model.ClassBroadcast, model.ClassDefault}
	pol := map[model.TrafficClass]ClassPolicy{
		model.ClassGaming:      {Pin: model.StickSession, PinTTL: 2 * time.Hour, Allowed: all},
		model.ClassVoIP:        {Pin: model.StickSession, PinTTL: 2 * time.Hour, Allowed: all},
		model.ClassStreaming:   {Pin: model.StickNone, Allowed: all},
		model.ClassBulk:        {Pin: model.StickNone, Allowed: wired},
		model.ClassIPSensitive: {Pin: model.StickDestination, PinTTL: 24 * time.Hour, Allowed: all},
		model.ClassBroadcast:   {Pin: model.StickDestination, PinTTL: 12 * time.Hour, Allowed: wired},
		model.ClassDefault:     {Pin: model.StickNone, Allowed: all},
	}
	user := []UserRule{{Name: "pc-torrent", Class: model.ClassBulk, Devices: []netip.Addr{netip.MustParseAddr("192.168.10.20")},
		Match: profile.Match{Proto: model.ProtoTCP, Ports: []profile.PortRange{{From: 40000, To: 40000}}}}}
	c := CompileClassify(classes, pol, user, cat)
	spec := testSpec()
	spec.Classify = c
	return spec, c
}

func TestCompileClassifyOrder(t *testing.T) {
	_, c := classifySpec(t)
	names := make([]string, len(c.Rules))
	for i, r := range c.Rules {
		names[i] = r.Name
	}
	pos := func(name string) int {
		i := slices.Index(names, name)
		if i < 0 {
			t.Fatalf("no rule %q in %v", name, names)
		}
		return i
	}
	// Порядок классификатора: пиры BitTorrent и правила пользователя →
	// ручные списки → профили (признак > домен > сеть > порт) → прочие списки.
	last := func(name string) int {
		i := pos(name)
		for j := range names {
			if names[j] == name {
				i = j
			}
		}
		return i
	}
	order := []string{"learned-torrent-peers", "pc-torrent", "list-manual-gaming", "calls/stun", "youtube/video", "minecraft/game", "list-default"}
	for i := 1; i < len(order); i++ {
		if pos(order[i-1]) > pos(order[i]) {
			t.Errorf("%s must come before %s: %v", order[i-1], order[i], names)
		}
	}
	// Сеть Valve (второй вариант steam/cm) — после доменов, до портов.
	if last("steam/cm") < pos("youtube/video") || last("steam/cm") > pos("minecraft/game") {
		t.Errorf("steam/cm by network out of place: %v", names)
	}
	// Поддомен раньше домена: gateway.discord.gg раньше discord.gg.
	if pos("discord/gateway") > pos("discord/app") {
		t.Errorf("discord gateway must precede discord app: %v", names)
	}
	// YouTube и Twitch закрепляются сервисом целиком.
	if !slices.Equal(c.Services, []string{"youtube", "twitch"}) {
		t.Errorf("services with pin = %v", c.Services)
	}
}

// Ни одно правило не совпадает по одному лишь протоколу: такое правило
// забрало бы весь TCP или UDP в свой класс.
func TestNoRuleMatchesWholeProtocol(t *testing.T) {
	_, c := classifySpec(t)
	for _, r := range c.Rules {
		e := strings.TrimSpace(matchExpr(r))
		if e == "" || e == "meta l4proto tcp" || e == "meta l4proto udp" {
			t.Errorf("rule %s matches too much: %q", r.Name, e)
		}
	}
}

func TestRenderClassifyRulesAndSets(t *testing.T) {
	spec, c := classifySpec(t)
	got := renderBase(spec)
	gid, vid, bid := c.classID(model.ClassGaming), c.classID(model.ClassVoIP), c.classID(model.ClassBulk)
	for _, want := range []string{
		// Правило пользователя: устройство + TCP-порт → bulk.
		`ip saddr 192.168.10.20 tcp dport 40000 meta mark set 0x4 goto cls4`,
		// STUN — по magic cookie в первом пакете UDP; голос Discord — по IP discovery.
		`meta l4proto udp @ih,32,32 0x2112a442 meta mark set 0x2 goto cls2`,
		`meta l4proto udp udp length 82 @ih,0,32 0x00010046 meta mark set 0x2 goto cls2`,
		// Домены YouTube — множество адресов (наполнит резолвер), цепочка сервиса.
		`ip daddr @tross_dp_youtube_video_0 meta mark set 0x3 goto svc0`,
		// Игровой UDP Steam — по портам.
		`udp dport 27000-27250 meta mark set 0x1 goto cls1`,
		// Пиры, узнанные по рукопожатию BitTorrent.
		`ip daddr . tcp dport @tross_btpeer4 meta mark set 0x4 goto cls4`,
		"set tross_dp_youtube_video_0 {\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t}",
		"set tross_btpeer4 {\n\t\ttype ipv4_addr . inet_service\n\t\tflags dynamic,timeout\n\t\ttimeout 3600s\n\t}",
		// Закрепления игр — по устройству на каждый канал; банков — устройство + адрес.
		"set tross_s1_0 {\n\t\ttype ipv4_addr\n\t\tflags dynamic,timeout\n\t\ttimeout 7200s\n\t}",
		"set tross_s5_2 {\n\t\ttype ipv4_addr . ipv4_addr\n\t\tflags dynamic,timeout\n\t\ttimeout 86400s\n\t}",
		"set tross_v0_0 {\n\t\ttype ipv4_addr\n\t\tflags dynamic,timeout\n\t\ttimeout 3600s\n\t}",
		// Торрент на LTE (вне каналов bulk) — пир запоминается, соединение рвётся;
		// проверка — до восстановления метки, иначе до неё не дошло бы.
		`iifname "lan" meta l4proto tcp ct state established ct original packets < 8 ct mark and 0xff00 == 0x300 @ih,0,96 0x13426974546f7272656e7420 update @tross_btpeer4 { ip daddr . tcp dport } reject with tcp reset`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("ruleset lacks:\n%s\n---\n%s", want, got)
		}
	}
	if gid != 1 || vid != 2 || bid != 4 {
		t.Fatalf("class ids gaming=%d voip=%d bulk=%d", gid, vid, bid)
	}
	if strings.Index(got, "reject with tcp reset") > strings.Index(got, "meta mark set ct mark and 0xffff return") {
		t.Error("BitTorrent guard must run before mark restore")
	}
	// Класс без закреплений (streaming) множеств закреплений не получает.
	if strings.Contains(got, "set tross_s3_") {
		t.Error("streaming has no pins but got sticky sets")
	}
}

func TestRenderPlanPinsAndReject(t *testing.T) {
	spec, c := classifySpec(t)
	plan := []decision.ClassPlan{
		{Class: model.ClassGaming, Shares: []decision.LinkShare{{Link: "isp1", Weight: 1}}, PinLinks: []model.LinkID{"isp1", "isp2"}},
		{Class: model.ClassIPSensitive, Shares: []decision.LinkShare{{Link: "isp1", Weight: 1}}, PinLinks: []model.LinkID{"isp1", "isp2"}},
		{Class: model.ClassBulk},
		{Class: model.ClassStreaming, Shares: []decision.LinkShare{{Link: "isp1", Weight: 1}}, PinLinks: []model.LinkID{"isp1", "isp2"}},
	}
	got := renderPlan(c, spec.Links, plan)
	for _, want := range []string{
		// Закреплённая сессия — на свой канал, мимо выбора.
		// Каждое новое соединение продлевает срок закрепления.
		"add rule inet tross cls1 ip saddr @tross_s1_0 update @tross_s1_0 { ip saddr } meta mark set 0x101 goto commit\n",
		"add rule inet tross cls1 ip saddr @tross_s1_1 update @tross_s1_1 { ip saddr } meta mark set 0x201 goto commit\n",
		// LTE в PinLinks нет — его закрепления очищаются.
		"flush set inet tross tross_s1_2\n",
		// Новая сессия: выбор + запоминание.
		"add rule inet tross cls1 meta mark set 0x101\n",
		"add rule inet tross cls1 meta mark and 0xff00 == 0x100 update @tross_s1_0 { ip saddr }\n",
		// Банк — устройство + адрес назначения.
		"add rule inet tross cls5 ip saddr . ip daddr @tross_s5_0 update @tross_s5_0 { ip saddr . ip daddr } meta mark set 0x105 goto commit\n",
		// bulk без пригодных каналов — отказ, а не основная таблица (там мог бы быть LTE).
		"flush chain inet tross cls4\nadd rule inet tross cls4 meta l4proto tcp reject with tcp reset\nadd rule inet tross cls4 reject\n",
		// Сервис YouTube — по плану своего класса (streaming).
		"add rule inet tross svc0 meta mark set 0x103\n",
		"add rule inet tross svc0 meta mark and 0xff00 == 0x100 update @tross_v0_0 { ip saddr }\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("plan lacks:\n%s---\n%s", want, got)
		}
	}
}

func TestInitialPlanRespectsAllowedLinks(t *testing.T) {
	spec, c := classifySpec(t)
	routed := map[model.LinkID]bool{"lte": true} // проводные без маршрута
	for _, p := range initialPlan(c, spec.Links, routed) {
		switch p.Class {
		case model.ClassBulk, model.ClassBroadcast:
			if len(p.Shares) != 0 {
				t.Errorf("%s got %v — LTE is not allowed", p.Class, p.Shares)
			}
		case model.ClassGaming:
			if len(p.Shares) != 1 || p.Shares[0].Link != "lte" {
				t.Errorf("gaming initial = %v, want lte", p.Shares)
			}
		}
	}
}

func TestMergePlanKeepsOtherClasses(t *testing.T) {
	prev := []decision.ClassPlan{{Class: "a", Shares: []decision.LinkShare{{Link: "isp1", Weight: 1}}}, {Class: "b"}}
	got := mergePlan(prev, []decision.ClassPlan{{Class: "b", Shares: []decision.LinkShare{{Link: "isp2", Weight: 1}}}})
	if len(got) != 2 || got[0].Shares[0].Link != "isp1" || got[1].Shares[0].Link != "isp2" {
		t.Fatalf("merge = %+v", got)
	}
	if !plansEqual(got, slices.Clone(got)) || plansEqual(got, prev) {
		t.Error("plansEqual")
	}
}
