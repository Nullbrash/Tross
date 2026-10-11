package daemon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math"
	"testing"
	"time"

	"tross/core/event"
	"tross/core/model"
	"tross/internal/linkmon"
	"tross/internal/store"
)

func TestSysSampler(t *testing.T) {
	files := map[string]string{
		"/proc/stat":        "cpu  100 0 50 800 10 5 20 0 0 0\n",
		"/proc/meminfo":     "MemTotal: 4194304 kB\nMemAvailable: 3145728 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n",
		"/proc/self/stat":   "42 (trossd) S 1 1 1 0 -1 0 0 0 0 0 100 50 0 0 20 0 8 0 1 1 1\n",
		"/proc/self/status": "Name: trossd\nVmRSS: 30720 kB\n",
		"/proc/self/io":     "write_bytes: 0\n",
	}
	s := newSysSampler(func(name string) ([]byte, error) {
		if v, ok := files[name]; ok {
			return []byte(v), nil
		}
		return nil, errors.New("no file")
	})
	t0 := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	if s.sample(t0) != nil {
		t.Fatal("first call only takes a baseline")
	}
	// За 60 с: из 1000 тиков машины 600 простоя → занято 40 %; демон — 300 тиков = 5 % ядра.
	files["/proc/stat"] = "cpu  300 0 150 1400 10 5 120 0 0 0\n"
	files["/proc/self/stat"] = "42 (trossd) S 1 1 1 0 -1 0 0 0 0 0 300 150 0 0 20 0 8 0 1 1 1\n"
	files["/proc/self/io"] = "write_bytes: 204800\n"
	got := s.sample(t0.Add(time.Minute))
	near := func(a, b float64) bool { return math.Abs(a-b) < 1e-9 }
	if got == nil || !near(got.CPUBusy, 40) || !near(got.CPUSoftIRQ, 10) || !near(got.ProcCPU, 5) ||
		!near(got.MemUsedMB, 1024) || !near(got.ProcRSSMB, 30) || !near(got.DiskWriteKB, 200) {
		t.Fatalf("sample = %+v", got)
	}
}

func TestSysSamplerUnavailable(t *testing.T) {
	s := newSysSampler(func(string) ([]byte, error) { return nil, errors.New("not linux") })
	if s.sample(time.Now()) != nil || s.sample(time.Now().Add(time.Minute)) != nil {
		t.Fatal("without /proc there must be no samples")
	}
}

func TestCollectorWritesDeltas(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open("", store.DefaultRetention())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	links := []model.Link{{ID: "isp1", Name: "isp1", Kind: model.LinkKindWired, Interface: "wan1"}}
	mon := linkmon.NewFake(links, event.NewBus(), time.Second, 1)
	c := newCollector(slog.New(slog.NewTextHandler(io.Discard, nil)), st, mon)
	c.sys = newSysSampler(func(string) ([]byte, error) { return nil, errors.New("off") })

	t0 := time.Date(2026, 10, 11, 12, 0, 30, 0, time.UTC)
	mon.Tick()
	c.collect(ctx, t0)
	first, _ := mon.Status("isp1")
	mon.Tick()
	mon.Tick()
	c.collect(ctx, t0.Add(time.Minute))
	cur, _ := mon.Status("isp1")

	rows, _ := st.LinkStats(ctx, "isp1", store.ResMinute, t0.Add(-time.Hour), t0.Add(time.Hour))
	if len(rows) != 1 || !rows[0].At.Equal(t0.Add(time.Minute).Truncate(time.Minute)) {
		t.Fatalf("first collect is a baseline only; rows = %+v", rows)
	}
	if rows[0].RxBytes != cur.Health.RxBytes-first.Health.RxBytes || rows[0].RxBytes == 0 {
		t.Fatalf("rx delta = %d, want %d", rows[0].RxBytes, cur.Health.RxBytes-first.Health.RxBytes)
	}
}

func TestCounterDelta(t *testing.T) {
	if counterDelta(100, 150) != 50 || counterDelta(1000, 30) != 30 {
		t.Fatal("counter delta")
	}
}
