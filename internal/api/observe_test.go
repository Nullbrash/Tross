package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"tross/core/model"
	"tross/internal/dataplane"
)

func observeServer(t *testing.T, got *model.Flow) http.Handler {
	t.Helper()
	conns := []dataplane.Connection{
		{Proto: "tcp", Src: netip.MustParseAddrPort("192.168.1.20:50000"), Dst: netip.MustParseAddrPort("198.51.100.9:443"), Link: "isp1", Class: model.ClassStreaming, State: "established", Timeout: time.Hour, Bytes: 900},
		{Proto: "udp", Src: netip.MustParseAddrPort("192.168.1.20:50001"), Dst: netip.MustParseAddrPort("203.0.113.7:27015"), Link: "isp2", Class: model.ClassGaming, Timeout: time.Minute, Bytes: 5000},
		{Proto: "tcp", Src: netip.MustParseAddrPort("192.168.1.21:50002"), Dst: netip.MustParseAddrPort("198.51.100.9:443"), Link: "isp1", Class: model.ClassStreaming, Bytes: 10},
	}
	return New(Options{
		Log:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		AllowedNetworks: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		Connections:     func(context.Context) ([]dataplane.Connection, error) { return conns, nil },
		Explain: func(_ context.Context, f model.Flow) (Explanation, error) {
			*got = f
			return Explanation{Flow: f, Reason: "test"}, nil
		},
	}).Handler()
}

func TestConnections(t *testing.T) {
	h := observeServer(t, new(model.Flow))
	var resp struct {
		Total       int                        `json:"total"`
		ByClass     map[model.TrafficClass]int `json:"by_class"`
		ByLink      map[model.LinkID]int       `json:"by_link"`
		Connections []connDTO                  `json:"connections"`
	}
	rec := do(h, "GET", "/api/connections?limit=1", "127.0.0.1:1")
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &resp) != nil {
		t.Fatalf("code %d: %s", rec.Code, rec.Body)
	}
	// Сводка — по всем, список — самые объёмные до limit.
	if resp.Total != 3 || resp.ByLink["isp1"] != 2 || resp.ByClass[model.ClassGaming] != 1 || len(resp.Connections) != 1 || resp.Connections[0].Bytes != 5000 || resp.Connections[0].TimeoutS != 60 {
		t.Errorf("resp = %+v", resp)
	}
	resp = struct {
		Total       int                        `json:"total"`
		ByClass     map[model.TrafficClass]int `json:"by_class"`
		ByLink      map[model.LinkID]int       `json:"by_link"`
		Connections []connDTO                  `json:"connections"`
	}{}
	rec = do(h, "GET", "/api/connections?device=192.168.1.20&link=isp1", "127.0.0.1:1")
	if json.Unmarshal(rec.Body.Bytes(), &resp) != nil || resp.Total != 1 || resp.Connections[0].Class != model.ClassStreaming {
		t.Errorf("filtered = %s", rec.Body)
	}
	if rec := do(h, "GET", "/api/connections?device=pc", "127.0.0.1:1"); rec.Code != http.StatusBadRequest {
		t.Errorf("bad device: code %d", rec.Code)
	}
}

func TestExplainQuery(t *testing.T) {
	var got model.Flow
	h := observeServer(t, &got)
	rec := do(h, "GET", "/api/explain?src=192.168.1.20&dst=198.51.100.9&port=443&domain=WWW.YouTube.com.", "127.0.0.1:1")
	var ex Explanation
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &ex) != nil {
		t.Fatalf("code %d: %s", rec.Code, rec.Body)
	}
	if got.Proto != model.ProtoTCP || got.Dst != netip.MustParseAddrPort("198.51.100.9:443") || got.Domain != "www.youtube.com" {
		t.Errorf("flow = %+v", got)
	}
	// Уже открытые соединения этого устройства к адресу и порту — из conntrack.
	if len(ex.Existing) != 1 || ex.Existing[0].Link != "isp1" || ex.Shares == nil || ex.Notes == nil {
		t.Errorf("explanation = %s", rec.Body)
	}
	for _, q := range []string{
		"src=192.168.1.20", // ни dst, ни domain
		"dst=198.51.100.9", // без устройства
		"src=192.168.1.20&dst=198.51.100.9&proto=icmp",
		"src=192.168.1.20&dst=::1",
		"src=192.168.1.20&domain=bad_domain!",
		"src=192.168.1.20&dst=198.51.100.9&port=0",
	} {
		if rec := do(h, "GET", "/api/explain?"+q, "127.0.0.1:1"); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: code %d", q, rec.Code)
		}
	}
	// Только домен — допустимо (адреса ещё нет).
	if rec := do(h, "GET", "/api/explain?src=192.168.1.20&domain=discord.gg&proto=udp", "127.0.0.1:1"); rec.Code != http.StatusOK || got.Dst.Addr().IsValid() {
		t.Errorf("domain only: code %d, flow %+v", rec.Code, got)
	}
}

func TestObserveUnavailable(t *testing.T) {
	h := newTestServer(t)
	for _, p := range []string{"/api/connections", "/api/explain?src=127.0.0.1&dst=1.1.1.1"} {
		if rec := do(h, "GET", p, "127.0.0.1:1"); rec.Code != http.StatusNotImplemented {
			t.Errorf("%s: code %d", p, rec.Code)
		}
	}
}
