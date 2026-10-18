package daemon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"

	corelists "tross/core/lists"
	"tross/core/model"
	"tross/internal/api"
	"tross/internal/config"
	"tross/internal/dataplane"
	"tross/internal/store"
)

func TestEncryptedDNS(t *testing.T) {
	ap := netip.MustParseAddrPort
	doh := map[netip.Addr]bool{netip.MustParseAddr("1.1.1.1"): true}
	conns := []dataplane.Connection{
		{Proto: "tcp", Src: ap("192.168.10.20:40000"), Dst: ap("9.9.9.9:853"), Class: model.ClassDefault},
		{Proto: "tcp", Src: ap("192.168.10.21:40001"), Dst: ap("1.1.1.1:443"), Class: model.ClassDefault},
		{Proto: "tcp", Src: ap("192.168.10.21:40002"), Dst: ap("1.1.1.1:443"), Class: model.ClassDefault},
		{Proto: "tcp", Src: ap("192.168.10.22:40003"), Dst: ap("203.0.113.5:443"), Class: model.ClassDefault}, // обычный сайт
		{Proto: "tcp", Src: ap("192.168.10.1:40004"), Dst: ap("9.9.9.9:853")},                                 // само мини-ПК
	}
	got := encryptedDNS(conns, doh)
	if len(got) != 2 || got[0].Kind != "dot" || got[0].Device != "192.168.10.20" || got[1].Kind != "doh" || len(got[1].Destinations) != 1 {
		t.Errorf("encrypted dns %+v", got)
	}
}

// Ответил тот, кому отвечать нечего, — перехват; молчание — нет.
func TestProbeIntercept(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 512)
		for {
			n, a, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			resp := append([]byte(nil), buf[:n]...)
			resp[2] |= 0x80
			_, _ = pc.WriteTo(resp, a)
		}
	}()
	d := &net.Dialer{}
	if !probeIntercept(context.Background(), d, netip.MustParseAddrPort(pc.LocalAddr().String())) {
		t.Error("answering interceptor not detected")
	}
	silent, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	defer silent.Close()
	if probeIntercept(context.Background(), d, netip.MustParseAddrPort(silent.LocalAddr().String())) {
		t.Error("silence reported as interception")
	}
}

// Правила из API — в базе и в слое ручных; правила конфига через API не
// удаляются.
func TestListsAPIManual(t *testing.T) {
	cfg := exampleCfg(t)
	cfg.Lists.Manual = []config.ListRule{{Domains: []string{"cfg.example"}, Purpose: corelists.PurposeNever}}
	st, err := store.Open("", store.DefaultRetention())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	rules := corelists.NewRules()
	ctx := context.Background()
	a, err := newListsAPI(ctx, cfg, nil, rules, st, log)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AddManual(ctx, api.ManualRule{Domain: "Video.Example", Purpose: model.PurposeClass, Class: model.ClassStreaming}); err != nil {
		t.Fatal(err)
	}
	if r, ok := rules.Lookup("www.video.example"); !ok || r.Class != model.ClassStreaming {
		t.Errorf("api rule not applied: %+v", r)
	}
	if r, ok := rules.Lookup("cfg.example"); !ok || r.Purpose != model.PurposeNever {
		t.Errorf("config rule lost: %+v", r)
	}
	for name, m := range map[string]api.ManualRule{
		"unknown class":   {Domain: "a.example", Purpose: model.PurposeClass, Class: "nope"},
		"no purpose":      {Domain: "a.example"},
		"class on bypass": {Domain: "a.example", Purpose: model.PurposeBypass, Class: model.ClassStreaming},
		"bad domain":      {Domain: "bad..", Purpose: model.PurposeBypass},
	} {
		if a.AddManual(ctx, m) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Перезапуск: правило из базы на месте.
	rules2 := corelists.NewRules()
	if _, err := newListsAPI(ctx, cfg, nil, rules2, st, log); err != nil {
		t.Fatal(err)
	}
	if _, ok := rules2.Lookup("video.example"); !ok {
		t.Error("api rule lost after restart")
	}
	if err := a.DeleteManual(ctx, "cfg.example", model.MatchSuffix); !errors.Is(err, api.ErrNotFound) {
		t.Errorf("config rule deleted through the api: %v", err)
	}
	if err := a.DeleteManual(ctx, "video.example", model.MatchSuffix); err != nil {
		t.Fatal(err)
	}
	if _, ok := rules.Lookup("video.example"); ok {
		t.Error("deleted rule still applies")
	}
}
