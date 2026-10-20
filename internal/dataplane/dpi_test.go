package dataplane

import (
	"strings"
	"testing"
)

func TestRenderDPI(t *testing.T) {
	spec := testSpec()
	if got := renderDPI(spec); got != "" {
		t.Fatalf("no dpi links, yet rules:\n%s", got)
	}
	if strings.Contains(renderBase(spec), "queue") {
		t.Fatal("base table queues without dpi")
	}
	spec.DPI = DPISpec{Links: []DPILink{{Index: 0, Queue: 200}, {Index: 1, Queue: 201}}}
	got := renderBase(spec)
	for _, want := range []string{
		"set tross_dpi0 {", "set tross_dpi1 {", "set tross_dpidev4 {",
		"type filter hook postrouting priority srcnat + 1;",
		"meta mark and 0x40000000 != 0 return",
		`oifname "wan1" tcp dport { 80, 443 } ct original packets 1-6 ip daddr @tross_dpi0 counter queue num 200 bypass`,
		`oifname "wan2" tcp dport { 80, 443 } ct original packets 1-6 ip daddr @tross_dpi1 counter queue num 201 bypass`,
		`oifname "wan1" tcp dport 443 ct original packets 1-6 ct original ip saddr @tross_dpidev4 counter queue num 200 bypass`,
		"type filter hook prerouting priority dstnat - 1;",
		`iifname "wan1" tcp sport { 80, 443 } ct reply packets 1-3 ip saddr @tross_dpi0 counter queue num 200 bypass`,
		`iifname "wan2" tcp sport 443 ct reply packets 1-3 ct original ip saddr @tross_dpidev4 counter queue num 201 bypass`,
		`oifname "wan1" udp dport 443 ip daddr @tross_dpi0 counter reject`,
		"type filter hook output priority raw;", "meta mark and 0x40000000 != 0 notrack",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q", want)
		}
	}
	// LTE без движка: ни множества, ни очереди.
	if strings.Contains(got, "tross_dpi2") || strings.Contains(got, `"wan3"`) && strings.Contains(got, "queue num 202") {
		t.Error("link without dpi got rules")
	}
	// Очередь — только с bypass: без движка трафик идёт мимо.
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, "queue num") && !strings.HasSuffix(line, " bypass") {
			t.Errorf("queue without bypass: %s", line)
		}
	}
}

func TestValidateDPI(t *testing.T) {
	spec := testSpec()
	spec.DPI = DPISpec{Links: []DPILink{{Index: 0, Queue: 200}, {Index: 1, Queue: 200}}}
	if validateDPI(spec) == nil {
		t.Error("shared queue accepted")
	}
	spec.DPI = DPISpec{Links: []DPILink{{Index: 5, Queue: 200}}}
	if validateDPI(spec) == nil {
		t.Error("index out of range accepted")
	}
	spec.DPI = DPISpec{Links: []DPILink{{Index: 2, Queue: 202}}}
	if err := validateDPI(spec); err != nil {
		t.Error(err)
	}
}
