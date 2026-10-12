package sdnotify

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
)

func TestNotifyWithoutSystemd(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	if err := Notify("READY=1"); err != nil {
		t.Fatalf("outside systemd Notify must be a no-op, got %v", err)
	}
}

func TestNotifySendsState(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("unixgram sockets: linux only")
	}
	path := filepath.Join(t.TempDir(), "notify.sock")
	ln, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	t.Setenv("NOTIFY_SOCKET", path)
	if err := Notify("WATCHDOG=1"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = ln.SetReadDeadline(time.Now().Add(time.Second))
	n, err := ln.Read(buf)
	if err != nil || string(buf[:n]) != "WATCHDOG=1" {
		t.Fatalf("got %q, %v", buf[:n], err)
	}
}

func TestWatchdogInterval(t *testing.T) {
	t.Setenv("WATCHDOG_USEC", "30000000")
	t.Setenv("WATCHDOG_PID", "")
	if got := WatchdogInterval(); got != 15*time.Second {
		t.Fatalf("interval = %v, want 15s", got)
	}
	t.Setenv("WATCHDOG_PID", strconv.Itoa(os.Getpid()+1))
	if got := WatchdogInterval(); got != 0 {
		t.Fatalf("watchdog for another pid must be ignored, got %v", got)
	}
	t.Setenv("WATCHDOG_USEC", "")
	if got := WatchdogInterval(); got != 0 {
		t.Fatalf("no watchdog: got %v", got)
	}
}
