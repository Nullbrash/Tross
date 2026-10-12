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
		"ct mark and 0xff00 != 0 meta mark set ct mark and 0xff00 return",
		`iifname "lan" ct state new jump choose`,
		"chain choose {\n\t}",
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

func TestRenderChooseSingleAndEmpty(t *testing.T) {
	spec := testSpec()
	got := renderChoose(spec.Links, []decision.LinkShare{{Link: "isp2", Weight: 1}})
	if !strings.Contains(got, "add rule inet tross choose meta mark set 0x200 ct mark set meta mark") {
		t.Fatalf("single link:\n%s", got)
	}
	for _, empty := range [][]decision.LinkShare{nil, {{Link: "isp1", Weight: 0}}, {{Link: "unknown", Weight: 5}}} {
		got = renderChoose(spec.Links, empty)
		if strings.Contains(got, "add rule") || !strings.HasPrefix(got, "flush chain inet tross choose") {
			t.Fatalf("no usable link must leave choose empty (%v):\n%s", empty, got)
		}
	}
}

func TestRenderChooseWeighted(t *testing.T) {
	spec := testSpec()
	got := renderChoose(spec.Links, []decision.LinkShare{{Link: "isp1", Weight: 75}, {Link: "isp2", Weight: 25}, {Link: "lte", Weight: 1}})
	want := "meta mark set jhash ip saddr . ip daddr mod 101 map { 0-74 : 0x100, 75-99 : 0x200, 100 : 0x300 } ct mark set meta mark"
	if !strings.Contains(got, want) {
		t.Fatalf("weighted choose:\n%s\nwant %s", got, want)
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
func TestRenderAddElementAndIfname(t *testing.T) {
	if got := renderAddElement(SetDPI, "203.0.113.5", 300); got != "add element inet tross tross_dpi4 { 203.0.113.5 timeout 300s }\n" {
		t.Fatalf("element = %q", got)
	}
	for name, ok := range map[string]bool{"wan1": true, "enp2s0": true, "": false, `a"b`: false, "a b": false, "0123456789abcdef": false} {
		if validIfname(name) != ok {
			t.Errorf("validIfname(%q) != %v", name, ok)
		}
	}
}
