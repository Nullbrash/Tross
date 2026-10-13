package api

import (
	"context"
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
	"tross/internal/logring"
	"tross/internal/store"
)

func newTestServer(t *testing.T) http.Handler {
	t.Helper()
	mon := linkmon.NewFake([]model.Link{
		{ID: "isp1", Name: "ISP 1", Kind: model.LinkKindWired, Interface: "eth1"},
		{ID: "lte", Name: "LTE", Kind: model.LinkKindLTE, Interface: "eth2", Metered: true},
	}, event.NewBus(), time.Second, 1)
	mon.Tick()
	st, err := store.Open("", store.DefaultRetention())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	at := time.Now().Add(-time.Hour).Truncate(time.Minute)
	_ = st.AppendSamples(context.Background(),
		[]store.LinkSample{{At: at, Link: "isp1", State: model.LinkStateUp, RTT: 5 * time.Millisecond, RxBytes: 100}},
		&store.SystemSample{At: at, CPUBusy: 12})
	_ = st.AppendEvent(context.Background(), event.Event{Topic: event.TopicDaemon, Time: at, Data: "started"})
	logs := logring.New(10)
	log := slog.New(logs.Wrap(slog.NewTextHandler(io.Discard, nil)))
	log.Info("hello", "k", "v")
	log.Warn("careful")
	return New(Options{
		Log:             log,
		Monitor:         mon,
		Store:           st,
		Logs:            logs,
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

func TestSpeedTest(t *testing.T) {
	h := newTestServer(t)
	rec := do(h, http.MethodPost, "/api/links/isp1/speedtest", "127.0.0.1:1")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"down_bps":500000000`) {
		t.Fatalf("speedtest: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(h, http.MethodPost, "/api/links/nope/speedtest", "127.0.0.1:1"); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown link: %d", rec.Code)
	}
	// GET попадает в общий «GET /api/» (404), а не в замер — трафик не тратится.
	if rec := do(h, http.MethodGet, "/api/links/isp1/speedtest", "127.0.0.1:1"); rec.Code != http.StatusNotFound {
		t.Fatalf("GET speedtest must not run the test, got %d", rec.Code)
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

func TestEventsAndLogs(t *testing.T) {
	h := newTestServer(t)
	rec := do(h, http.MethodGet, "/api/events?limit=5", "127.0.0.1:1")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"topic":"daemon"`) || !strings.Contains(rec.Body.String(), `"data":"started"`) {
		t.Fatalf("events: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(h, http.MethodGet, "/api/events?since=yesterday", "127.0.0.1:1"); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad since: %d", rec.Code)
	}
	rec = do(h, http.MethodGet, "/api/logs?level=warn", "127.0.0.1:1")
	var logs struct{ Logs []struct{ Msg, Level string } }
	_ = json.Unmarshal(rec.Body.Bytes(), &logs)
	if rec.Code != http.StatusOK || len(logs.Logs) != 1 || logs.Logs[0].Msg != "careful" {
		t.Fatalf("logs: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(h, http.MethodGet, "/api/logs?level=loud", "127.0.0.1:1"); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad level: %d", rec.Code)
	}
}

func TestStatsAndMetrics(t *testing.T) {
	h := newTestServer(t)
	rec := do(h, http.MethodGet, "/api/links/isp1/stats?res=minute", "127.0.0.1:1")
	var body struct {
		Stats []struct {
			RTT float64 `json:"rtt_avg_ms"`
			Rx  uint64  `json:"rx_bytes"`
		}
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != http.StatusOK || len(body.Stats) != 1 || body.Stats[0].RTT != 5 || body.Stats[0].Rx != 100 {
		t.Fatalf("link stats: %d %s", rec.Code, rec.Body.String())
	}
	// Сводок ещё нет — пустой список, а не null.
	if rec := do(h, http.MethodGet, "/api/links/isp1/stats", "127.0.0.1:1"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"stats":[]`) {
		t.Fatalf("hour stats: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(h, http.MethodGet, "/api/system/stats?res=minute", "127.0.0.1:1"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"cpu_avg":12`) {
		t.Fatalf("system stats: %d %s", rec.Code, rec.Body.String())
	}
	for path, want := range map[string]int{
		"/api/links/nope/stats":                                  http.StatusNotFound,
		"/api/links/isp1/stats?res=week":                         http.StatusBadRequest,
		"/api/system/stats?res=minute&from=2026-01-01T00:00:00Z": http.StatusBadRequest, // окно больше недели
	} {
		if rec := do(h, http.MethodGet, path, "127.0.0.1:1"); rec.Code != want {
			t.Errorf("%s: %d, want %d", path, rec.Code, want)
		}
	}
	rec = do(h, http.MethodGet, "/api/metrics", "127.0.0.1:1")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"goroutines"`) || !strings.Contains(rec.Body.String(), `"rx_bytes"`) ||
		!strings.Contains(rec.Body.String(), `"system":null`) || !strings.Contains(rec.Body.String(), `"event_drops":0`) {
		t.Fatalf("metrics: %d %s", rec.Code, rec.Body.String())
	}
}

func TestEmptyLogsIsList(t *testing.T) {
	h := New(Options{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Logs: logring.New(5),
		AllowedNetworks: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}).Handler()
	if rec := do(h, http.MethodGet, "/api/logs", "127.0.0.1:1"); !strings.Contains(rec.Body.String(), `"logs":[]`) {
		t.Fatalf("empty logs: %s", rec.Body.String())
	}
}

func TestSystemSampleJSON(t *testing.T) {
	b, _ := json.Marshal(store.SystemSample{CPUBusy: 1})
	if !strings.Contains(string(b), `"cpu_busy":1`) {
		t.Fatalf("system sample json: %s", b)
	}
}
