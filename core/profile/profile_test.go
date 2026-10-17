package profile

import (
	"net/netip"
	"slices"
	"testing"

	"tross/core/model"
)

func flow(proto model.Protocol, dst, domain, sig string) model.Flow {
	return model.Flow{Proto: proto, Src: netip.MustParseAddrPort("192.168.10.20:50000"),
		Dst: netip.MustParseAddrPort(dst), Domain: domain, Signature: sig}
}

func TestBuiltinCatalog(t *testing.T) {
	c, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name          string
		f             model.Flow
		service, part string
		class         model.TrafficClass
	}{
		{"steam cm by domain", flow(model.ProtoTCP, "155.133.230.10:443", "cmp2-sto2.steamserver.net", ""), "steam", "cm", model.ClassIPSensitive},
		{"steam cm by valve network", flow(model.ProtoTCP, "162.254.198.5:27020", "", ""), "steam", "cm", model.ClassIPSensitive},
		{"steam download", flow(model.ProtoTCP, "93.184.1.1:443", "cache4-ams1.steamcontent.com", ""), "steam", "download", model.ClassBulk},
		{"steam game udp", flow(model.ProtoUDP, "1.2.3.4:27015", "", ""), "steam", "game", model.ClassGaming},
		{"steam voice on valve network", flow(model.ProtoUDP, "155.133.240.1:3478", "", ""), "steam", "p2p-voice", model.ClassVoIP},
		{"steam game via valve relay", flow(model.ProtoUDP, "155.133.240.1:27020", "", ""), "steam", "game", model.ClassGaming},
		{"youtube video", flow(model.ProtoTCP, "8.8.8.8:443", "rr2---sn-aigl6nze.googlevideo.com", ""), "youtube", "video", model.ClassStreaming},
		{"youtube live ingest", flow(model.ProtoTCP, "8.8.8.8:443", "a.rtmp.youtube.com", ""), "youtube", "live", model.ClassBroadcast},
		{"twitch ingest", flow(model.ProtoTCP, "1.1.1.1:1935", "live-fra.contribute.live-video.net", ""), "twitch", "live", model.ClassBroadcast},
		{"discord gateway beats app", flow(model.ProtoTCP, "1.1.1.1:443", "gateway.discord.gg", ""), "discord", "gateway", model.ClassIPSensitive},
		{"discord app", flow(model.ProtoTCP, "1.1.1.1:443", "discord.gg", ""), "discord", "app", model.ClassDefault},
		{"discord voice signature", flow(model.ProtoUDP, "66.22.200.1:50004", "", SigDiscordVoice), "discord", "voice", model.ClassVoIP},
		{"discord updates", flow(model.ProtoTCP, "1.1.1.1:443", "updates.discord.com", ""), "discord", "updates", model.ClassBulk},
		{"stun call", flow(model.ProtoUDP, "5.5.5.5:3479", "", SigSTUN), "calls", "stun", model.ClassVoIP},
		{"torrent utp", flow(model.ProtoUDP, "5.5.5.5:51413", "", SigUTP), "torrent", "peers", model.ClassBulk},
		{"minecraft server", flow(model.ProtoTCP, "5.5.5.5:25565", "", ""), "minecraft", "game", model.ClassGaming},
		{"minecraft auth", flow(model.ProtoTCP, "5.5.5.5:443", "sessionserver.mojang.com", ""), "minecraft", "auth", model.ClassIPSensitive},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, ok := c.Lookup(tc.f)
			if !ok || h.Service != tc.service || h.Part.ID != tc.part || h.Part.Class != tc.class {
				t.Fatalf("Lookup = %v %s/%s %s; want %s/%s %s", ok, h.Service, h.Part.ID, h.Part.Class, tc.service, tc.part, tc.class)
			}
		})
	}
	// Голос Steam — только в сети Valve: тот же порт к чужому адресу — не Steam.
	if h, ok := c.Lookup(flow(model.ProtoUDP, "5.5.5.5:3478", "", "")); ok {
		t.Errorf("udp 3478 outside Valve network matched %s/%s", h.Service, h.Part.ID)
	}
	// Без признаков ничего не узнаётся.
	if h, ok := c.Lookup(flow(model.ProtoTCP, "5.5.5.5:443", "example.org", "")); ok {
		t.Errorf("unrelated flow matched %s/%s", h.Service, h.Part.ID)
	}
	if h, _ := c.Lookup(flow(model.ProtoTCP, "8.8.8.8:443", "www.youtube.com", "")); !h.Part.PinService {
		t.Error("youtube video must pin the whole service to one link")
	}
}

func TestUserOverridesBuiltin(t *testing.T) {
	c, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	user := []Service{
		{ID: "steam", Disabled: true},
		{ID: "myserver", Parts: []Part{{ID: "mc", Class: model.ClassGaming, Match: []Match{{Proto: model.ProtoTCP, Ports: []PortRange{{25570, 25570}}}}}}},
	}
	c = c.WithUser(user)
	if h, ok := c.Lookup(flow(model.ProtoUDP, "1.2.3.4:27015", "", "")); ok {
		t.Errorf("disabled steam still matched %s/%s", h.Service, h.Part.ID)
	}
	if h, ok := c.Lookup(flow(model.ProtoTCP, "5.5.5.5:25570", "", "")); !ok || h.Service != "myserver" {
		t.Errorf("user service not matched: %v %s", ok, h.Service)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidate(t *testing.T) {
	bad := map[string]string{
		"duplicate service": "services: [{id: a, parts: [{id: p, class: default, match: [{ports: ['1']}]}]}, {id: a, parts: []}]",
		"no class":          "services: [{id: a, parts: [{id: p, match: [{ports: ['1']}]}]}]",
		"empty match":       "services: [{id: a, parts: [{id: p, class: default, match: [{proto: tcp}]}]}]",
		"bad domain":        "services: [{id: a, parts: [{id: p, class: default, match: [{domains: [Example.ORG]}]}]}]",
		"unmasked network":  "services: [{id: a, parts: [{id: p, class: default, match: [{networks: [10.0.0.1/8]}]}]}]",
		"bad ports":         "services: [{id: a, parts: [{id: p, class: default, match: [{ports: ['30-20']}]}]}]",
		"unknown field":     "services: [{id: a, oops: 1}]",
	}
	for name, y := range bad {
		if _, err := Parse([]byte(y)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if r, err := ParsePortRange(" 27000-27250 "); err != nil || r != (PortRange{27000, 27250}) {
		t.Errorf("ParsePortRange = %v %v", r, err)
	}
}

func TestCatalogDomains(t *testing.T) {
	cat, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	all, ok := cat.Domains("steam")
	if !ok || !slices.Contains(all, "steamcontent.com") || !slices.Contains(all, "steampowered.com") {
		t.Errorf("steam: %v %v", all, ok)
	}
	store, ok := cat.Domains("steam/store")
	if !ok || slices.Contains(store, "steamcontent.com") || !slices.Contains(store, "steampowered.com") {
		t.Errorf("steam/store: %v %v", store, ok)
	}
	if _, ok := cat.Domains("steam/shop"); ok {
		t.Error("unknown part found")
	}
	if _, ok := cat.Domains("netflix"); ok {
		t.Error("unknown service found")
	}
	off := cat.WithUser([]Service{{ID: "steam", Disabled: true}})
	if d, ok := off.Domains("steam"); !ok || len(d) != 0 {
		t.Errorf("disabled service: %v %v — want known, no domains", d, ok)
	}
}
