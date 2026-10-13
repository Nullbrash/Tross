package daemon

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"slices"
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
	cfg.Daemon.DataDir = t.TempDir()
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

	// События идут в базу через шину асинхронно — ждём «started».
	base := "http://127.0.0.1:" + port
	for deadline := time.Now().Add(3 * time.Second); ; {
		var body struct{ Events []struct{ Topic string } }
		resp, err := http.Get(base + "/api/events")
		if err == nil {
			err = json.NewDecoder(resp.Body).Decode(&body)
			resp.Body.Close()
		}
		if err == nil && slices.ContainsFunc(body.Events, func(e struct{ Topic string }) bool { return e.Topic == "daemon" }) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("events not stored: %v %+v", err, body)
		}
		time.Sleep(20 * time.Millisecond)
	}
	resp, err := http.Get(base + "/api/metrics")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("metrics: %v %v", resp, err)
	}
	var m struct {
		DBSize int64 `json:"db_size_bytes"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&m)
	resp.Body.Close()
	if m.DBSize == 0 {
		t.Fatal("database file must exist in the data dir")
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
	cfg.Daemon.DataDir = t.TempDir()
	err = Run(context.Background(), Options{Config: cfg, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err == nil {
		t.Fatal("expected listen error on busy port")
	}
}

// TestDryRunWithoutDataDirKeepsStoreInMemory — «сухой» запуск без каталога
// данных не создаёт файлов (на машине разработчика путь по умолчанию
// оказался бы в корне текущего диска).
func TestDryRunWithoutDataDirKeepsStoreInMemory(t *testing.T) {
	port := freePort(t)
	cfg, err := config.Parse([]byte(strings.ReplaceAll(testConfig, "%PORT%", port)))
	if err != nil {
		t.Fatal(err)
	}
	cfg.SetDataDir("")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{Config: cfg, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	}()
	var m struct {
		DBSize *int64 `json:"db_size_bytes"`
	}
	for deadline := time.Now().Add(3 * time.Second); ; {
		resp, err := http.Get("http://127.0.0.1:" + port + "/api/metrics")
		if err == nil {
			err = json.NewDecoder(resp.Body).Decode(&m)
			resp.Body.Close()
		}
		if err == nil && m.DBSize != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("metrics not served: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if *m.DBSize != 0 {
		t.Fatalf("db size %d: store must live in memory", *m.DBSize)
	}
}
