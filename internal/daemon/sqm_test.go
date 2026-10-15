package daemon

import (
	"context"
	"io"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"tross/core/event"
	"tross/core/model"
	"tross/core/sqm"
	"tross/internal/config"
	"tross/internal/dataplane"
)

const sqmYAML = `
lan: { interface: br0, networks: [192.168.1.0/24] }
links:
  - { id: isp1, kind: wired, interface: eth1, sqm: { enabled: true, down_mbit: 100, up_mbit: 20 } }
  - { id: isp2, kind: wired, interface: eth2, sqm: { enabled: true } }
  - { id: lte, kind: lte, interface: eth3 }
dns: { listen: ["192.168.1.1:53"] }
`

func sqmBench(t *testing.T, before ...dataplane.Shaping) (*sqmController, *dataplane.Fake, *event.Bus) {
	t.Helper()
	cfg, err := config.Parse([]byte(sqmYAML))
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	dp := dataplane.NewFake(log)
	// Очереди, оставшиеся в ядре от прошлого запуска.
	if len(before) > 0 {
		_ = dp.SetShaping(context.Background(), before)
	}
	bus := event.NewBus()
	c := newSQMController(cfg, log, dp, bus)
	c.start(context.Background())
	return c, dp, bus
}

func shapingOps(dp *dataplane.Fake) []string {
	var out []string
	for _, op := range dp.Ops() {
		if strings.HasPrefix(op, "set-shaping") {
			out = append(out, op)
		}
	}
	return out
}

func TestSQMStartManualAndRestored(t *testing.T) {
	c, dp, _ := sqmBench(t, dataplane.Shaping{Link: "isp2", DownBps: 450_000_000, UpBps: 180_000_000})
	st := c.status()
	if _, ok := st["lte"]; ok {
		t.Error("lte without sqm got a queue")
	}
	// База из конфига — сразу, 90 %.
	if q := st["isp1"]; q.Down.RateBps != 90_000_000 || q.Up.RateBps != 18_000_000 || q.Down.Basis != string(sqm.BasisManual) {
		t.Errorf("isp1 = %+v", q)
	}
	// Скорость из ядра после перезапуска не сбрасывается до «без ограничения».
	if q := st["isp2"]; q.Down.RateBps != 450_000_000 || q.Down.Basis != string(sqm.BasisRestored) {
		t.Errorf("isp2 = %+v", q)
	}
	if ops := shapingOps(dp); !slices.Contains(ops, "set-shaping [isp1 90000000 18000000]") {
		t.Errorf("start ops: %v", ops)
	}
}

func TestSQMFollowsDelayUnderLoad(t *testing.T) {
	c, dp, bus := sqmBench(t)
	events, unsub := bus.Subscribe(16, event.TopicSQM)
	defer unsub()
	ctx := context.Background()
	at := time.Date(2026, 10, 15, 21, 0, 0, 0, time.UTC)
	round := func(down uint64, rtt time.Duration) {
		c.observe(ctx, at, event.LinkRound{Link: "isp1", DownBps: down, UpBps: 1_000_000, RTTs: map[string]time.Duration{"a": rtt, "b": rtt + 20*time.Millisecond}})
		at = at.Add(2 * time.Second)
	}
	round(1_000_000, 8*time.Millisecond) // базовая задержка в простое
	for range 10 {
		round(90_000_000, 48*time.Millisecond) // очередь копится у провайдера
	}
	q := c.status()["isp1"]
	if q.Down.Pct >= 90 || q.Down.RateBps >= 90_000_000 {
		t.Errorf("rate did not go down under bloat: %+v", q.Down)
	}
	if q.Up.Pct != 90 {
		t.Errorf("upload is idle, must stay: %+v", q.Up)
	}
	ops := shapingOps(dp)
	if len(ops) < 2 {
		t.Errorf("rates not applied: %v", ops)
	}
	// За 20 с несколько шагов, а событие — одно (не чаще раза в минуту).
	if n := len(events); n != 1 {
		t.Errorf("%d sqm events in 20 s, want 1", n)
	}
}

func TestSQMSpeedTestLiftsDownload(t *testing.T) {
	c, dp, _ := sqmBench(t)
	done := c.speedTestHook("isp2")
	if q := c.status()["isp2"]; !q.Testing {
		t.Error("status must show the test")
	}
	done(model.Throughput{DownBps: 500_000_000, MeasuredAt: time.Now()}, nil)
	q := c.status()["isp2"]
	if q.Testing || q.Down.Basis != string(sqm.BasisTest) || q.Down.RateBps != 450_000_000 {
		t.Errorf("after test: %+v", q)
	}
	// База из конфига тест не меняет.
	c.speedTestHook("isp1")(model.Throughput{DownBps: 900_000_000}, nil)
	if q := c.status()["isp1"]; q.Down.RateBps != 90_000_000 {
		t.Errorf("manual base overridden by test: %+v", q.Down)
	}
	t.Logf("ops: %v", shapingOps(dp))
}

// Раунды монитора не попадают в журнал и историю: их пишет только журнал
// по своим темам.
func TestRoundsNotJournaled(t *testing.T) {
	if slices.Contains(event.JournalTopics(), event.TopicLinkRound) {
		t.Error("link rounds must not be journaled")
	}
	if !slices.Contains(event.JournalTopics(), event.TopicSQM) {
		t.Error("sqm changes must be journaled")
	}
}

// Под нагрузкой не ответила ни одна проба (буфер у провайдера длиннее
// таймаута проб) — это раздутость: база находится сразу, не дожидаясь,
// пока монитор сочтёт канал упавшим. Без нагрузки молчание — не повод.
func TestSQMLostProbesUnderLoad(t *testing.T) {
	c, _, _ := sqmBench(t)
	ctx := context.Background()
	at := time.Date(2026, 10, 15, 21, 0, 0, 0, time.UTC)
	c.observe(ctx, at, event.LinkRound{Link: "isp2", DownBps: 300_000})
	if q := c.status()["isp2"]; q.Down.RateBps != 0 {
		t.Fatalf("idle silence set a rate: %+v", q.Down)
	}
	c.observe(ctx, at.Add(2*time.Second), event.LinkRound{Link: "isp2", DownBps: 180_000_000, UpBps: 2_000_000})
	if q := c.status()["isp2"]; q.Down.Basis != string(sqm.BasisPassive) || q.Down.RateBps != 162_000_000 {
		t.Errorf("lost probes under load: %+v", q.Down)
	}
}
