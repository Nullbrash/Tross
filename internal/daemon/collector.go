package daemon

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"time"

	"tross/core/model"
	"tross/internal/linkmon"
	"tross/internal/procfs"
	"tross/internal/store"
)

// userHZ — тиков в секунду в /proc (на amd64 Linux всегда 100).
const userHZ = 100

// collector раз в минуту пишет выборки каналов и машины одной транзакцией
// (одна запись на диск в минуту) и раз в час запускает сводки и очистку.
type collector struct {
	log *slog.Logger
	st  store.Store
	mon linkmon.LinkMonitor
	sys *sysSampler

	prev       map[model.LinkID][2]uint64
	lastRollup time.Time

	mu   sync.RWMutex
	last *store.SystemSample
}

func newCollector(log *slog.Logger, st store.Store, mon linkmon.LinkMonitor) *collector {
	return &collector{log: log, st: st, mon: mon, sys: newSysSampler(os.ReadFile), prev: map[model.LinkID][2]uint64{}}
}

func (c *collector) run(ctx context.Context, every time.Duration) {
	// Базовые снимки счётчиков: первая запись через минуту будет уже разностью.
	c.collect(ctx, time.Now())
	c.rollup(ctx, time.Now())
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			c.collect(ctx, now)
			if now.Truncate(time.Hour) != c.lastRollup.Truncate(time.Hour) {
				c.rollup(ctx, now)
			}
		}
	}
}

func (c *collector) rollup(ctx context.Context, now time.Time) {
	c.lastRollup = now
	if err := c.st.Rollup(ctx, now); err != nil && ctx.Err() == nil {
		c.log.Warn("store rollup", "err", err)
	}
}

func (c *collector) collect(ctx context.Context, now time.Time) {
	at := now.Truncate(time.Minute)
	var links []store.LinkSample
	for _, s := range c.mon.Snapshot() {
		h := s.Health
		if h.UpdatedAt.IsZero() {
			continue
		}
		prev, seen := c.prev[s.Link.ID]
		c.prev[s.Link.ID] = [2]uint64{h.RxBytes, h.TxBytes}
		if !seen {
			continue
		}
		links = append(links, store.LinkSample{
			At: at, Link: s.Link.ID, State: h.State, RTT: h.RTT, Jitter: h.Jitter, Loss: h.Loss,
			RxBytes: counterDelta(prev[0], h.RxBytes), TxBytes: counterDelta(prev[1], h.TxBytes),
		})
	}
	sys := c.sys.sample(now)
	if sys != nil {
		sys.At = at
		c.mu.Lock()
		c.last = sys
		c.mu.Unlock()
	}
	if len(links) == 0 && sys == nil {
		return
	}
	if err := c.st.AppendSamples(ctx, links, sys); err != nil && ctx.Err() == nil {
		c.log.Warn("store samples", "err", err)
	}
}

// Last — последняя выборка машины (nil, если её ещё нет или /proc недоступен).
func (c *collector) Last() *store.SystemSample {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.last
}

// counterDelta — прирост счётчика; меньшее значение значит пересоздание
// интерфейса (счётчик начат с нуля), и тогда прирост — само значение.
func counterDelta(prev, cur uint64) uint64 {
	if cur < prev {
		return cur
	}
	return cur - prev
}

// sysSampler считает загрузку машины и демона между вызовами по /proc.
// Чтение файлов подменяется в тестах; вне Linux чтение не удаётся и выборок нет.
type sysSampler struct {
	read func(string) ([]byte, error)

	ok     bool
	at     time.Time
	cpu    procfs.CPUTimes
	ticks  uint64
	writes uint64
}

func newSysSampler(read func(string) ([]byte, error)) *sysSampler {
	return &sysSampler{read: read}
}

func (s *sysSampler) sample(now time.Time) *store.SystemSample {
	text := func(name string) string {
		b, err := s.read(name)
		if err != nil {
			return ""
		}
		return string(b)
	}
	cpu, err := procfs.ParseCPU(text("/proc/stat"))
	if err != nil {
		s.ok = false
		return nil
	}
	mem, _ := procfs.ParseMeminfo(text("/proc/meminfo"))
	ut, stt, _ := procfs.ParseProcStat(text("/proc/self/stat"))
	rss, _ := procfs.ParseVmRSS(text("/proc/self/status"))
	wb, _ := procfs.ParseIOWriteBytes(text("/proc/self/io"))

	prevOK, prevAt, prevCPU, prevTicks, prevWrites := s.ok, s.at, s.cpu, s.ticks, s.writes
	s.ok, s.at, s.cpu, s.ticks, s.writes = true, now, cpu, ut+stt, wb
	dt := now.Sub(prevAt).Seconds()
	if !prevOK || dt <= 0 {
		return nil
	}
	share := procfs.CPUDelta(prevCPU, cpu)
	return &store.SystemSample{
		CPUBusy:     100 - share.Idle - share.IOWait,
		CPUSoftIRQ:  share.SoftIRQ,
		MemUsedMB:   float64(mem.TotalKB-min(mem.AvailableKB, mem.TotalKB)) / 1024,
		ProcCPU:     float64(counterDelta(prevTicks, ut+stt)) / userHZ / dt * 100,
		ProcRSSMB:   float64(rss) / 1024,
		DiskWriteKB: float64(counterDelta(prevWrites, wb)) / 1024,
	}
}
