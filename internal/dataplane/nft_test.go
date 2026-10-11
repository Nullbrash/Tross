package dataplane

import (
	"strings"
	"testing"

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
		`oifname { "wan1", "wan2", "wan3" } masquerade`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("base ruleset lacks %q\n---\n%s", want, got)
		}
	}
}

func TestRenderChooseByPriority(t *testing.T) {
	spec := testSpec()
	all := map[model.LinkID]bool{"isp1": true, "isp2": true, "lte": true}
	got := renderChoose(spec.Links, all)
	// isp2 приоритетнее (10 < 20), хоть и второй в конфиге.
	if !strings.Contains(got, "meta mark set 0x200 ct mark set meta mark") {
		t.Fatalf("expected isp2 chosen:\n%s", got)
	}
	got = renderChoose(spec.Links, map[model.LinkID]bool{"isp1": true, "lte": true})
	if !strings.Contains(got, "meta mark set 0x100") {
		t.Fatalf("expected fallback to isp1:\n%s", got)
	}
	got = renderChoose(spec.Links, map[model.LinkID]bool{})
	if strings.Contains(got, "add rule") || !strings.HasPrefix(got, "flush chain inet tross choose") {
		t.Fatalf("no usable link must leave choose empty:\n%s", got)
	}
}

func TestRenderChooseStableOnEqualPriority(t *testing.T) {
	spec := testSpec()
	for i := range spec.Links {
		spec.Links[i].Link.Priority = 0
	}
	got := renderChoose(spec.Links, map[model.LinkID]bool{"isp2": true, "isp1": true})
	if !strings.Contains(got, "0x100") {
		t.Fatalf("equal priority must keep config order:\n%s", got)
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
