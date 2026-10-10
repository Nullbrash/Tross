package daemon

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"tross/internal/config"
)

const testConfig = `
daemon: { dry_run: true }
api: { listen: "127.0.0.1:%PORT%" }
lan: { interface: br0, networks: [192.168.1.0/24] }
links:
  - { id: isp1, kind: wired, interface: eth1 }
  - { id: lte, kind: lte, interface: eth2 }
monitor: { interval: 50ms, timeout: 20ms }
dns: { listen: ["192.168.1.1:53"] }
`

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return port
}

func TestRunServesAndStops(t *testing.T) {
	port := freePort(t)
	cfg, err := config.Parse([]byte(strings.ReplaceAll(testConfig, "%PORT%", port)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{Config: cfg, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Version: "test"})
	}()

	url := "http://127.0.0.1:" + port + "/api/links"
	var links struct{ Links []struct{ ID, State string } }
	deadline := time.Now().Add(3 * time.Second)
	for {
		resp, err := http.Get(url)
		if err == nil {
			err = json.NewDecoder(resp.Body).Decode(&links)
			resp.Body.Close()
		}
		if err == nil && len(links.Links) == 2 && links.Links[0].State == "up" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("daemon did not serve links in time: %v %+v", err, links)
		}
		time.Sleep(20 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v after cancel", err)
		}
	case <-time.After(shutdownTimeout + time.Second):
		t.Fatal("daemon did not stop after cancel")
	}
	if _, err := http.Get(url); err == nil {
		t.Fatal("api still serving after shutdown")
	}
}

func TestRunFailsOnBusyPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	cfg, err := config.Parse([]byte(strings.ReplaceAll(testConfig, "%PORT%", port)))
	if err != nil {
		t.Fatal(err)
	}
	err = Run(context.Background(), Options{Config: cfg, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err == nil {
		t.Fatal("expected listen error on busy port")
	}
}
