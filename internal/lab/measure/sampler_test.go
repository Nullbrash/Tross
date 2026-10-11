package measure

import (
	"tross/internal/procfs"

	"math"
	"strings"
	"testing"
	"time"
)

func TestDiff(t *testing.T) {
	t0 := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	mk := func(sec int, idle, user, sect, ticks, rx uint64) Snapshot {
		return Snapshot{
			At:       t0.Add(time.Duration(sec) * time.Second),
			CPU:      procfs.CPUTimes{User: user, Idle: idle},
			Mem:      procfs.Mem{TotalKB: 4 << 20, AvailableKB: 3 << 20},
			DiskSect: sect,
			ProcPID:  42,
			Proc:     procfs.ProcStat{UTime: ticks, RSSKB: 20 << 10},
			Net:      map[string][]IfaceBytes{"tl-tross": {{Name: "wan1", RxBytes: rx}}},
		}
	}
	start := mk(0, 0, 0, 0, 0, 0)
	prev := mk(1, 100, 0, 2048, 10, 1_000_000)
	cur := mk(3, 250, 50, 4096, 60, 3_500_000)

	r, nets := Diff(start, prev, cur)
	near := func(a, b float64) bool { return math.Abs(a-b) < 1e-9 }
	if !near(r.CPU.Idle, 75) || !near(r.CPU.User, 25) {
		t.Fatalf("cpu = %+v", r.CPU)
	}
	if !near(r.MemUsedMB, 1024) {
		t.Fatalf("mem used = %v", r.MemUsedMB)
	}
	// 2048 секторов × 512 Б = 1 МиБ за 2 с.
	if !near(r.DiskWriteKBps, 512) || !near(r.DiskWrittenMB, 2) {
		t.Fatalf("disk = %v KB/s, %v MB", r.DiskWriteKBps, r.DiskWrittenMB)
	}
	// 50 тиков за 2 с при USER_HZ=100 → 25 % одного ядра.
	if !near(r.ProcCPUPct, 25) || !near(r.ProcRSSMB, 20) {
		t.Fatalf("proc = %v %%, %v MB", r.ProcCPUPct, r.ProcRSSMB)
	}
	if len(nets) != 1 || !near(nets[0].RxMbps, 2.5*8/2) || !near(nets[0].RxTotalMB, 3.5) {
		t.Fatalf("net = %+v", nets)
	}
	if len(r.Record()) != len(SystemHeader) || len(nets[0].Record()) != len(NetHeader) {
		t.Fatal("record width must match header")
	}

	var sum Summary
	sum.Add(r, nets)
	var b strings.Builder
	sum.Write(&b, 3)
	if !strings.Contains(b.String(), "tl-tross/wan1") || !strings.Contains(b.String(), "samples: 1") {
		t.Fatalf("summary:\n%s", b.String())
	}
}

func TestDiffProcessRestart(t *testing.T) {
	t0 := time.Now()
	prev := Snapshot{At: t0, ProcPID: 1, Proc: procfs.ProcStat{UTime: 1000}}
	cur := Snapshot{At: t0.Add(time.Second), ProcPID: 2, Proc: procfs.ProcStat{UTime: 5, RSSKB: 1024}}
	r, _ := Diff(prev, prev, cur)
	// Новый PID: тики не сравнимы — ЦП не считаем, иначе получим мусор от переполнения.
	if r.ProcCPUPct != 0 || r.ProcRSSMB != 1 {
		t.Fatalf("restart handling: %+v", r)
	}
}
