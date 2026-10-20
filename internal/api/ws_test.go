package api

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/websocket"

	"tross/core/event"
	"tross/core/model"
	"tross/internal/linkmon"
)

func TestWebSocketStream(t *testing.T) {
	bus := event.NewBus()
	h := New(Options{NoAuth: true, Log: quietLog(), Monitor: testMonitor(), AllowedNetworks: loopback(),
		Events: func() (<-chan event.Event, func()) { return bus.Subscribe(16) }}).Handler()
	srv := httptest.NewServer(h)
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/ws"
	cfg, _ := websocket.NewConfig(url, srv.URL)
	c, err := websocket.DialConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var m map[string]any
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if err := websocket.JSON.Receive(c, &m); err != nil || m["type"] != "links" {
		t.Fatalf("first message %v %v", m, err)
	}
	time.Sleep(50 * time.Millisecond)
	bus.Publish(event.Event{Topic: event.TopicDeviceNew, Data: "x"})
	for {
		if err := websocket.JSON.Receive(c, &m); err != nil {
			t.Fatal(err)
		}
		if m["type"] == "event" {
			break
		}
	}
	if m["topic"] != "device.new" {
		t.Errorf("event %v", m)
	}
	// Чужая страница — отказ.
	bad, _ := websocket.NewConfig(url, "https://evil.example")
	if _, err := websocket.DialConfig(bad); err == nil {
		t.Error("cross-origin websocket accepted")
	}
	// Без Origin (не браузер) — тоже отказ.
	r := httptest.NewRequest("GET", "/api/ws", nil)
	r.RemoteAddr = "127.0.0.1:1"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("no origin: %d", w.Code)
	}
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func loopback() []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")} }

func testMonitor() linkmon.LinkMonitor {
	m := linkmon.NewFake([]model.Link{{ID: "isp1", Name: "ISP 1", Kind: model.LinkKindWired, Interface: "eth1"}}, event.NewBus(), time.Second, 1)
	m.Tick()
	return m
}
