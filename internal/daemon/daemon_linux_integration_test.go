//go:build linux && integration

package daemon

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"tross/internal/config"
)

// TestRealModeOnBench — демон целиком в реальном режиме внутри tl-tross:
// каналы поднимаются по настоящим пробам, после остановки в ядре не
// остаётся ничего демона.
func TestRealModeOnBench(t *testing.T) {
	path := "configs/lab.yaml" // lab-itest запускает бинарник из корня репозитория
	if _, err := os.Stat(path); err != nil {
		path = "../../configs/lab.yaml"
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Daemon.DataDir = t.TempDir()
	if cfg.Daemon.DryRun {
		t.Fatal("lab config must run in real mode")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{Config: cfg, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Version: "itest"})
	}()

	url := "http://" + cfg.API.Listen + "/api/links"
	deadline := time.Now().Add(15 * time.Second)
	for {
		var body struct{ Links []struct{ ID, State string } }
		resp, err := http.Get(url)
		if err == nil {
			err = json.NewDecoder(resp.Body).Decode(&body)
			resp.Body.Close()
		}
		up := 0
		for _, l := range body.Links {
			if l.State == "up" {
				up++
			}
		}
		if err == nil && up == 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("links not up via real monitor: %v %+v", err, body.Links)
		}
		time.Sleep(200 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("daemon did not stop")
	}
	if out, _ := exec.Command("ip", "rule").Output(); strings.Contains(string(out), "fwmark") {
		t.Fatalf("ip rules left after shutdown:\n%s", out)
	}
	if err := exec.Command("nft", "list", "table", "inet", "tross").Run(); err == nil {
		t.Fatal("nft table left after shutdown")
	}
}
