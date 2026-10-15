package dataplane

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"tross/core/model"
)

func TestDecodeMark(t *testing.T) {
	spec, c := classifySpec(t)
	gid := c.classID(model.ClassGaming)
	for _, tc := range []struct {
		mark  uint32
		link  model.LinkID
		class model.TrafficClass
	}{
		{0x100 | gid, "isp1", model.ClassGaming},
		{0x200 | c.classID(model.ClassDefault), "isp2", model.ClassDefault},
		{0x300, "lte", ""}, // собственный трафик машины: только канал
		{0x900 | 0xfe, "", ""},
	} {
		link, class := decodeMark(spec, tc.mark)
		if link != tc.link || class != tc.class {
			t.Errorf("decodeMark(%#x) = %q, %q; want %q, %q", tc.mark, link, class, tc.link, tc.class)
		}
	}
}

// Каждое множество, которое читает Pins, ставится Setup, и наоборот.
func TestPinSetsMatchRenderedSets(t *testing.T) {
	spec, _ := classifySpec(t)
	got := renderBase(spec)
	sets := pinSets(spec)
	for _, ps := range sets {
		if !strings.Contains(got, "\tset "+ps.name+" {") {
			t.Errorf("pin set %s is not in the ruleset", ps.name)
		}
	}
	n := strings.Count(got, "\tset tross_s") + strings.Count(got, "\tset tross_v")
	if n != len(sets) {
		t.Errorf("ruleset has %d pin sets, pinSets knows %d", n, len(sets))
	}
}

func TestParsePinSet(t *testing.T) {
	single := pinSet{name: "tross_s1_0", class: model.ClassGaming, link: "isp1"}
	data := `{"nftables": [{"metainfo": {"version": "1.1.3"}}, {"set": {"family": "inet", "name": "tross_s1_0", "table": "tross", "type": "ipv4_addr", "flags": ["timeout", "dynamic"], "timeout": 7200,
		"elem": [{"elem": {"val": "192.168.77.10", "timeout": 7200, "expires": 7195}}, "192.168.77.11"]}}]}`
	pins, err := parsePinSet(single, []byte(data))
	if err != nil {
		t.Fatal(err)
	}
	want := []Pin{
		{Class: model.ClassGaming, Device: netip.MustParseAddr("192.168.77.10"), Link: "isp1", Expires: 7195 * time.Second},
		{Class: model.ClassGaming, Device: netip.MustParseAddr("192.168.77.11"), Link: "isp1"},
	}
	if len(pins) != len(want) || pins[0] != want[0] || pins[1] != want[1] {
		t.Errorf("pins = %+v", pins)
	}

	pair := pinSet{name: "tross_s5_1", class: model.ClassIPSensitive, link: "isp2", withDst: true}
	data = `{"nftables": [{"set": {"name": "tross_s5_1", "type": ["ipv4_addr", "ipv4_addr"],
		"elem": [{"elem": {"val": {"concat": ["192.168.77.10", "203.0.113.5"]}, "expires": 60}}]}}]}`
	pins, err = parsePinSet(pair, []byte(data))
	if err != nil || len(pins) != 1 || pins[0].Dst != netip.MustParseAddr("203.0.113.5") || pins[0].Expires != time.Minute {
		t.Errorf("pair pins = %+v, %v", pins, err)
	}

	// Пустое множество — без поля elem.
	if pins, err := parsePinSet(single, []byte(`{"nftables": [{"set": {"name": "tross_s1_0"}}]}`)); err != nil || len(pins) != 0 {
		t.Errorf("empty set = %+v, %v", pins, err)
	}
	// Пара в множестве одиночных адресов — ошибка, а не тихий пропуск.
	if _, err := parsePinSet(single, []byte(`{"nftables": [{"set": {"elem": [{"elem": {"val": {"concat": ["1.1.1.1", "2.2.2.2"]}}}]}}]}`)); err == nil {
		t.Error("pair in single-address set accepted")
	}
}
