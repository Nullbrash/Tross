package classify

import (
	"net/netip"
	"testing"

	"tross/core/model"
	"tross/core/profile"
)

func flow(src string, proto model.Protocol, dst, domain, sig string) model.Flow {
	return model.Flow{Proto: proto, Src: netip.MustParseAddrPort(src), Dst: netip.MustParseAddrPort(dst), Domain: domain, Signature: sig}
}

const pc, tv = "192.168.10.20:50000", "192.168.10.30:50000"

func TestClassifyLayers(t *testing.T) {
	cat, err := profile.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	lists := map[string]model.DomainRule{
		// Ручное правило пользователя важнее профиля YouTube.
		"music.youtube.com": {Pattern: "music.youtube.com", Layer: model.LayerManual, Class: model.ClassBulk, Source: "user"},
		// Онлайн-список не перебивает профиль.
		"www.youtube.com": {Pattern: "youtube.com", Layer: model.LayerOnline, Class: model.ClassDefault, Source: "v2fly"},
		"cdn.example.org": {Pattern: "example.org", Layer: model.LayerOnline, Class: model.ClassStreaming, Source: "v2fly"},
	}
	e, err := New(Config{
		Catalog: cat,
		Domains: func(d string) (model.DomainRule, bool) { r, ok := lists[d]; return r, ok },
		Rules: []Rule{
			// Торрент-клиент ПК слушает этот порт: входящие к нему — загрузки.
			{Name: "pc-torrent-port", Class: model.ClassBulk, Devices: []string{"192.168.10.20"}, Match: profile.Match{Ports: []profile.PortRange{{From: 40000, To: 40000}}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		f      model.Flow
		class  model.TrafficClass
		source string
		conf   float64
	}{
		{"user rule for the device", flow(pc, model.ProtoTCP, "5.5.5.5:40000", "", ""), model.ClassBulk, "rule:pc-torrent-port", 1},
		{"same port, other device — not the rule", flow(tv, model.ProtoTCP, "5.5.5.5:40000", "", ""), model.ClassDefault, "default", 0.1},
		{"manual list beats profile", flow(pc, model.ProtoTCP, "8.8.8.8:443", "music.youtube.com", ""), model.ClassBulk, "list:user", 1},
		{"profile beats online list", flow(pc, model.ProtoTCP, "8.8.8.8:443", "www.youtube.com", ""), model.ClassStreaming, "profile:youtube/video", 0.9},
		{"online list when no profile", flow(pc, model.ProtoTCP, "8.8.8.8:443", "cdn.example.org", ""), model.ClassStreaming, "list:v2fly", 0.7},
		{"signature", flow(pc, model.ProtoUDP, "5.5.5.5:3479", "", profile.SigSTUN), model.ClassVoIP, "profile:calls/stun", 0.95},
		{"network", flow(pc, model.ProtoTCP, "162.254.198.5:27020", "", ""), model.ClassIPSensitive, "profile:steam/cm", 0.8},
		{"port only", flow(pc, model.ProtoTCP, "5.5.5.5:25565", "", ""), model.ClassGaming, "profile:minecraft/game", 0.6},
		{"default", flow(pc, model.ProtoTCP, "5.5.5.5:443", "", ""), model.ClassDefault, "default", 0.1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := e.Classify(tc.f)
			if c.Class != tc.class || c.Source != tc.source || c.Confidence != tc.conf {
				t.Fatalf("Classify = %+v; want %s from %s (%.2f)", c, tc.class, tc.source, tc.conf)
			}
		})
	}
	if c := e.Classify(flow(pc, model.ProtoTCP, "8.8.8.8:443", "rr1.googlevideo.com", "")); !c.PinService || c.Service != "youtube" {
		t.Errorf("youtube video: %+v, want service pin", c)
	}
}

func TestNewRejectsBadRules(t *testing.T) {
	if _, err := New(Config{Rules: []Rule{{Name: "x", Match: profile.Match{Ports: []profile.PortRange{{From: 1, To: 1}}}}}}); err == nil {
		t.Error("rule without class accepted")
	}
	if _, err := New(Config{Rules: []Rule{{Name: "x", Class: model.ClassBulk, Match: profile.Match{Proto: model.ProtoTCP}}}}); err == nil {
		t.Error("rule matching all TCP accepted")
	}
}
