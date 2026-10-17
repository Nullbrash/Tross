package dataplane

import (
	"strings"
	"testing"

	"tross/core/decision"
	"tross/core/model"
)

func testSpec() Spec {
	return Spec{
		LANInterface: "lan",
		Links: []LinkSpec{
			{Link: model.Link{ID: "isp1", Interface: "wan1", Priority: 20}, Table: 101, FwMark: 0x100},
			{Link: model.Link{ID: "isp2", Interface: "wan2", Priority: 10}, Table: 102, FwMark: 0x200},
			{Link: model.Link{ID: "lte", Interface: "wan3", Priority: 100}, Table: 103, FwMark: 0x300},
		},
	}
}

func TestRenderBase(t *testing.T) {
	got := renderBase(testSpec())
	for _, want := range []string{
		"add table inet tross\ndelete table inet tross\ntable inet tross {",
		"set tross_dpi4 {", "set tross_proxy4 {", "flags timeout",
		"type filter hook prerouting priority mangle;",
		"ct mark and 0xff00 != 0 meta mark set ct mark and 0x700ffff return",
		`iifname "lan" ct state new jump classify`,
		// Без классов — один default: всё в его цепочку, как прежний choose.
		"chain classify {\n\t\tmeta mark set 0x1 goto cls1\n\t}",
		"chain cls1 {\n\t}", "chain commit {\n\t\tct mark set meta mark\n\t}",
		"type route hook output priority mangle;",
		"meta mark and 0xff00 != 0 ct mark set meta mark and 0xff00",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("base ruleset lacks %q\n---\n%s", want, got)
		}
	}
	// NAT — в отдельной таблице: её не снимает остановка демона.
	if strings.Contains(got, "masquerade") {
		t.Errorf("masquerade must live in the NAT table, not in inet tross")
	}
}

func TestRenderNAT(t *testing.T) {
	got := renderNAT(testSpec())
	for _, want := range []string{
		"add table inet tross_nat\ndelete table inet tross_nat\ntable inet tross_nat {",
		"type nat hook postrouting priority srcnat;",
		`oifname { "wan1", "wan2", "wan3" } masquerade`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("NAT ruleset lacks %q\n---\n%s", want, got)
		}
	}
}

// defaultPlan — план одного класса default (как SetBalance).
func defaultPlan(shares ...decision.LinkShare) []decision.ClassPlan {
	return []decision.ClassPlan{{Class: model.ClassDefault, Shares: shares}}
}

func TestRenderPlanSingleAndEmpty(t *testing.T) {
	spec := testSpec()
	c := spec.Classify.withDefault()
	got := renderPlan(c, spec.Links, defaultPlan(decision.LinkShare{Link: "isp2", Weight: 1}))
	// Метка — канал (0x200) и класс default (0x1).
	for _, want := range []string{"flush chain inet tross cls1\n", "add rule inet tross cls1 meta mark set 0x201\n", "add rule inet tross cls1 goto commit\n"} {
		if !strings.Contains(got, want) {
			t.Fatalf("single link lacks %q:\n%s", want, got)
		}
	}
	// Ни одного канала: default разрешает все каналы — без метки, по
	// основной таблице (fail-open), не reject.
	for _, empty := range [][]decision.LinkShare{nil, {{Link: "isp1", Weight: 0}}, {{Link: "unknown", Weight: 5}}} {
		got = renderPlan(c, spec.Links, defaultPlan(empty...))
		if strings.Contains(got, "add rule") || !strings.HasPrefix(got, "flush chain inet tross cls1") {
			t.Fatalf("no usable link must leave cls1 empty (%v):\n%s", empty, got)
		}
	}
}

func TestRenderPlanWeighted(t *testing.T) {
	spec := testSpec()
	got := renderPlan(spec.Classify.withDefault(), spec.Links, defaultPlan(
		decision.LinkShare{Link: "isp1", Weight: 75}, decision.LinkShare{Link: "isp2", Weight: 25}, decision.LinkShare{Link: "lte", Weight: 1}))
	want := "meta mark set jhash ip saddr . ip daddr mod 101 map { 0-74 : 0x101, 75-99 : 0x201, 100 : 0x301 }"
	if !strings.Contains(got, want) {
		t.Fatalf("weighted plan:\n%s\nwant %s", got, want)
	}
}

func TestFirstByPriority(t *testing.T) {
	spec := testSpec()
	routed := map[model.LinkID]bool{"isp1": true, "isp2": true, "lte": true}
	// isp2 приоритетнее (10 < 20), хоть и второй в конфиге.
	if got := firstByPriority(spec.Links, routed); len(got) != 1 || got[0].Link != "isp2" {
		t.Fatalf("got %v", got)
	}
	for i := range spec.Links {
		spec.Links[i].Link.Priority = 0
	}
	if got := firstByPriority(spec.Links, map[model.LinkID]bool{"isp2": true, "isp1": true}); got[0].Link != "isp1" {
		t.Fatalf("equal priority must keep config order: %v", got)
	}
	if got := firstByPriority(spec.Links, nil); got != nil {
		t.Fatalf("nothing routed: %v", got)
	}
}

func TestValidIfname(t *testing.T) {
	for name, ok := range map[string]bool{"wan1": true, "enp2s0": true, "": false, `a"b`: false, "a b": false, "0123456789abcdef": false} {
		if validIfname(name) != ok {
			t.Errorf("validIfname(%q) != %v", name, ok)
		}
	}
}
