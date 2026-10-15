package dataplane

import (
	"strings"
	"testing"

	"tross/core/decision"
	"tross/core/model"
	"tross/core/sqm"
	"tross/internal/config"
)

// Корзина класса едет в метке с самого выбора класса до conntrack: правило
// классификации, выбор канала и закрепление ставят её вместе с каналом.
func TestTinBitsInClassMarks(t *testing.T) {
	spec, c := classifySpec(t)
	for cl, tin := range map[model.TrafficClass]sqm.Tin{model.ClassGaming: sqm.TinVoice, model.ClassBulk: sqm.TinBulk, model.ClassStreaming: sqm.TinVideo} {
		p := c.Policies[cl]
		p.Tin = tin
		c.Policies[cl] = p
	}
	spec.Classify = c
	base := renderBase(spec)
	for _, want := range []string{
		// Игровой UDP Steam — класс 1, корзина «голос» (4).
		`udp dport 27000-27250 meta mark set 0x4000001 goto cls1`,
		// Правило пользователя «торрент» — класс 4, корзина «фон» (1).
		`tcp dport 40000 meta mark set 0x1000004 goto cls4`,
		// Восстановление метки сохраняет корзину.
		`meta mark set ct mark and 0x700ffff return`,
	} {
		if !strings.Contains(base, want) {
			t.Errorf("ruleset lacks %q", want)
		}
	}
	plan := renderPlan(c, spec.Links, []decision.ClassPlan{
		{Class: model.ClassGaming, Shares: []decision.LinkShare{{Link: "isp1", Weight: 1}}, PinLinks: []model.LinkID{"isp1"}},
		{Class: model.ClassBulk, Shares: []decision.LinkShare{{Link: "isp1", Weight: 1}, {Link: "isp2", Weight: 1}}, PinLinks: []model.LinkID{"isp1", "isp2"}},
	})
	for _, want := range []string{
		"add rule inet tross cls1 ip saddr @tross_s1_0 update @tross_s1_0 { ip saddr } meta mark set 0x4000101 goto commit\n",
		"add rule inet tross cls1 meta mark set 0x4000101\n",
		"0 : 0x1000104, 1 : 0x1000204",
	} {
		if !strings.Contains(plan, want) {
			t.Errorf("plan lacks %q:\n%s", want, plan)
		}
	}
	// Класс без корзины — метка как раньше (корзину выберет CAKE по DSCP).
	if !strings.Contains(base, "meta mark set 0x7 goto cls7") {
		t.Errorf("default class without tin must keep a plain mark:\n%s", base)
	}
}

func TestTinMaskFree(t *testing.T) {
	for name, m := range map[string]uint32{"link": LinkMarkMask, "class": classMarkMask, "proxy": 0x00ff0000, "zapret": 0x40000000} {
		if TinMarkMask&m != 0 {
			t.Errorf("tin mask %#x overlaps %s %#x", TinMarkMask, name, m)
		}
	}
	// CAKE берёт номер корзины сдвигом маски — 1…4 должны в неё влезать.
	if uint32(sqm.TinVoice)<<tinShift&^TinMarkMask != 0 {
		t.Error("voice tin does not fit the mask")
	}
}

func TestRenderShaping(t *testing.T) {
	setup := renderShapingSetup("wan1", ifbName(0), Shaping{Link: "isp1", DownBps: 450_000_000})
	for _, want := range []string{
		// Отдача: без замера — без ограничения, деление по устройствам дома.
		"qdisc replace dev wan1 root cake unlimited diffserv4 dual-srchost nat fwmark 0x7000000\n",
		// Загрузка: метка из conntrack до перенаправления в IFB.
		"filter add dev wan1 parent ffff: pref 49152 handle 1 matchall action connmark action mirred egress redirect dev ifb-tross0\n",
		"qdisc replace dev ifb-tross0 root cake bandwidth 450000000bit diffserv4 dual-dsthost nat ingress fwmark 0x7000000\n",
	} {
		if !strings.Contains(setup, want) {
			t.Errorf("setup lacks:\n%s---\n%s", want, setup)
		}
	}
	rates := renderShapingRates("wan1", ifbName(0), Shaping{DownBps: 400_000_000, UpBps: 180_000_000})
	if rates != "qdisc change dev wan1 root cake bandwidth 180000000bit\nqdisc change dev ifb-tross0 root cake bandwidth 400000000bit\n" {
		t.Errorf("rates:\n%s", rates)
	}
	if n := len(ifbName(254)); n > 15 {
		t.Errorf("ifb name %q is %d bytes, kernel limit 15", ifbName(254), n)
	}
}

// Маска корзин в конфиге и в dataplane — одна и та же.
func TestTinMaskMatchesConfig(t *testing.T) {
	if config.TinMarkMask != TinMarkMask {
		t.Errorf("config %#x, dataplane %#x", config.TinMarkMask, TinMarkMask)
	}
}
