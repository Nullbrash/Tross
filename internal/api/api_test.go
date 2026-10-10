package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"tross/core/event"
	"tross/core/model"
	"tross/internal/linkmon"
)

func newTestServer(t *testing.T) http.Handler {
	t.Helper()
	mon := linkmon.NewFake([]model.Link{
		{ID: "isp1", Name: "ISP 1", Kind: model.LinkKindWired, Interface: "eth1"},
		{ID: "lte", Name: "LTE", Kind: model.LinkKindLTE, Interface: "eth2", Metered: true},
	}, event.NewBus(), time.Second, 1)
	mon.Tick()
	return New(Options{
		Log:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		Monitor:         mon,
		AllowedNetworks: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("192.168.1.0/24")},
		Version:         "test",
		DryRun:          true,
	}).Handler()
}

func do(h http.Handler, method, path, remote string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHealth(t *testing.T) {
	rec := do(newTestServer(t), http.MethodGet, "/api/health", "127.0.0.1:5000")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var h healthResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &h); err != nil {
		t.Fatal(err)
	}
	if h.Status != "ok" || h.Version != "test" || !h.DryRun {
		t.Fatalf("health = %+v", h)
	}
}

func TestLinks(t *testing.T) {
	rec := do(newTestServer(t), http.MethodGet, "/api/links", "192.168.1.20:40000")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var body struct{ Links []linkDTO }
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Links) != 2 || body.Links[0].ID != "isp1" || body.Links[1].ID != "lte" {
		t.Fatalf("links = %+v", body.Links)
	}
	if body.Links[0].State != model.LinkStateUp || body.Links[0].RTTms <= 0 || !body.Links[1].Metered {
		t.Fatalf("link fields wrong: %+v", body.Links)
	}
}

func TestRejectsOutsideNetworks(t *testing.T) {
	h := newTestServer(t)
	for _, remote := range []string{"203.0.113.7:1234", "[2001:db8::1]:1234", "garbage"} {
		if rec := do(h, http.MethodGet, "/api/health", remote); rec.Code != http.StatusForbidden {
			t.Errorf("%s: status = %d, want 403", remote, rec.Code)
		}
	}
	// IPv4-mapped IPv6 из разрешённой сети — это тот же клиент.
	if rec := do(h, http.MethodGet, "/api/health", "[::ffff:192.168.1.5]:1234"); rec.Code != http.StatusOK {
		t.Errorf("mapped LAN address: status = %d, want 200", rec.Code)
	}
}

func TestRoutingEdges(t *testing.T) {
	h := newTestServer(t)
	if rec := do(h, http.MethodGet, "/api/nope", "127.0.0.1:1"); rec.Code != http.StatusNotFound {
		t.Errorf("unknown api path: status = %d, want 404", rec.Code)
	}
	if rec := do(h, http.MethodPost, "/api/health", "127.0.0.1:1"); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST health: status = %d, want 405", rec.Code)
	}
	rec := do(h, http.MethodGet, "/", "127.0.0.1:1")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<title>Tross</title>") {
		t.Errorf("index: status = %d", rec.Code)
	}
}
