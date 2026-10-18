package store

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"tross/core/event"
	"tross/core/model"
)

func openMem(t *testing.T) *SQLite {
	t.Helper()
	s, err := Open("", DefaultRetention())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestRulesByLayer(t *testing.T) {
	ctx := context.Background()
	s := openMem(t)
	rules := []model.DomainRule{
		{Pattern: "b.com", Match: model.MatchSuffix, Layer: model.LayerManual, Source: "user"},
		{Pattern: "a.com", Match: model.MatchSuffix, Layer: model.LayerManual, Source: "user"},
		{Pattern: "a.com", Match: model.MatchSuffix, Layer: model.LayerOnline, Source: "itdog"},
	}
	for _, r := range rules {
		if err := s.SaveRule(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	// Повторное сохранение — замена, не дубль.
	rules[0].Source = "edited"
	if err := s.SaveRule(ctx, rules[0]); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Rules(ctx, model.LayerManual)
	if len(got) != 2 || got[0].Pattern != "a.com" || got[1].Source != "edited" {
		t.Fatalf("manual rules = %+v", got)
	}
	if err := s.DeleteRule(ctx, KeyOf(rules[1])); err != nil {
		t.Fatal(err)
	}
	got, _ = s.Rules(ctx, model.LayerManual)
	if len(got) != 1 || got[0].Pattern != "b.com" {
		t.Fatalf("after delete = %+v", got)
	}
	if err := s.SaveRule(ctx, model.DomainRule{Pattern: "BAD", Match: model.MatchExact, Layer: model.LayerManual}); err == nil {
		t.Fatal("invalid rule must be rejected")
	}
}

func TestDevicesRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := openMem(t)
	seen := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	d := model.Device{ID: "d1", Name: "phone", MACs: []model.MAC{{2, 0, 0, 0, 0, 1}}, FirstSeen: seen, LastSeen: seen}
	if err := s.SaveDevice(ctx, d); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveDevice(ctx, model.Device{}); err == nil {
		t.Fatal("empty id must be rejected")
	}
	got, err := s.Devices(ctx)
	if err != nil || len(got) != 1 || got[0].Name != "phone" || !got[0].LastSeen.Equal(seen) || len(got[0].MACs) != 1 {
		t.Fatalf("devices = %+v, %v", got, err)
	}
	_ = s.DeleteDevice(ctx, "d1")
	if got, _ := s.Devices(ctx); len(got) != 0 {
		t.Fatalf("after delete = %+v", got)
	}
}

func TestEventsSinceAndLimit(t *testing.T) {
	ctx := context.Background()
	s := openMem(t)
	base := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	for i := range 5 {
		_ = s.AppendEvent(ctx, event.Event{Topic: event.TopicLinkState, Time: base.Add(time.Duration(i) * time.Minute), Data: map[string]int{"i": i}})
	}
	all, _ := s.Events(ctx, time.Time{}, 0)
	if len(all) != 5 || !all[0].Time.Equal(base) {
		t.Fatalf("all = %+v", all)
	}
	last, _ := s.Events(ctx, base.Add(2*time.Minute), 2)
	if len(last) != 2 || !last[0].Time.Equal(base.Add(3*time.Minute)) || !last[1].Time.Equal(base.Add(4*time.Minute)) {
		t.Fatalf("since+limit must return the newest, ascending: %+v", last)
	}
	var data struct{ I int }
	if err := json.Unmarshal(last[1].Data.(json.RawMessage), &data); err != nil || data.I != 4 || last[1].Topic != event.TopicLinkState {
		t.Fatalf("event data = %v, %v", last[1].Data, err)
	}
}

func TestClosed(t *testing.T) {
	s, _ := Open("", DefaultRetention())
	_ = s.Close()
	if err := s.SaveDevice(context.Background(), model.Device{ID: "x"}); !errors.Is(err, ErrClosed) {
		t.Fatalf("SaveDevice after close = %v, want ErrClosed", err)
	}
	if _, err := s.Devices(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("Devices after close = %v, want ErrClosed", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("double close = %v", err)
	}
}

func TestRollupHourAndDay(t *testing.T) {
	ctx := context.Background()
	s := openMem(t)
	day := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	// Час 10:00–11:00: 60 минут, RTT = 1..60 мс, канал лежит первые 6 минут.
	for m := range 60 {
		at := day.Add(10*time.Hour + time.Duration(m)*time.Minute)
		st, rtt := model.LinkStateUp, time.Duration(m+1)*time.Millisecond
		if m < 6 {
			st, rtt = model.LinkStateDown, 0
		}
		l := LinkSample{At: at, Link: "isp1", State: st, RTT: rtt, Jitter: time.Millisecond, Loss: 0.01, RxBytes: 1000, TxBytes: 10}
		sys := &SystemSample{At: at, CPUBusy: float64(m), MemUsedMB: 500, ProcRSSMB: 30, DiskWriteKB: 2}
		if err := s.AppendSamples(ctx, []LinkSample{l}, sys); err != nil {
			t.Fatal(err)
		}
	}
	// Текущий незакрытый час — не должен попасть в сводку.
	_ = s.AppendSamples(ctx, []LinkSample{{At: day.Add(11*time.Hour + time.Minute), Link: "isp1", State: model.LinkStateUp, RTT: time.Second}}, nil)

	now := day.Add(11*time.Hour + 5*time.Minute)
	if err := s.Rollup(ctx, now); err != nil {
		t.Fatal(err)
	}
	hours, err := s.LinkStats(ctx, "isp1", ResHour, day, now)
	if err != nil || len(hours) != 1 {
		t.Fatalf("hour stats = %+v, %v", hours, err)
	}
	h := hours[0]
	// RTT по 54 пригодным минутам: 7..60 мс; p95 ближайшим рангом = 58.
	if h.Samples != 60 || h.UsableMinutes != 54 || h.RTTMin != 7 || h.RTTMax != 60 || h.RTTP95 != 58 || h.RxBytes != 60000 {
		t.Fatalf("hour = %+v", h)
	}
	sys, _ := s.SystemStats(ctx, ResHour, day, now)
	if len(sys) != 1 || sys[0].CPUMax != 59 || sys[0].DiskWriteKB != 120 || sys[0].Samples != 60 {
		t.Fatalf("sys hour = %+v", sys)
	}
	// Повторный вызов в том же часе ничего не пересчитывает и не дублирует.
	_ = s.Rollup(ctx, now.Add(time.Minute))
	if hours, _ = s.LinkStats(ctx, "isp1", ResHour, day, now); len(hours) != 1 {
		t.Fatalf("rollup must be idempotent: %+v", hours)
	}
	if days, _ := s.LinkStats(ctx, "isp1", ResDay, day, now); len(days) != 0 {
		t.Fatalf("day is not closed yet: %+v", days)
	}

	// Следующие сутки — день 10.10 закрыт.
	next := day.Add(24*time.Hour + time.Hour)
	if err := s.Rollup(ctx, next); err != nil {
		t.Fatal(err)
	}
	days, _ := s.LinkStats(ctx, "isp1", ResDay, day, next)
	if len(days) != 1 || days[0].Samples != 61 || days[0].RTTMax != 1000 {
		t.Fatalf("day = %+v", days)
	}
	mins, _ := s.LinkStats(ctx, "isp1", ResMinute, day.Add(10*time.Hour), day.Add(10*time.Hour+2*time.Minute))
	if len(mins) != 2 || mins[0].UsableMinutes != 0 || mins[0].Samples != 1 {
		t.Fatalf("minutes = %+v", mins)
	}
}

func TestRollupRetention(t *testing.T) {
	ctx := context.Background()
	ret := Retention{Minute: 2 * time.Hour, Hour: 48 * time.Hour, Day: 10 * 24 * time.Hour, Events: 24 * time.Hour}
	s, err := Open("", ret)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	_ = s.AppendSamples(ctx, []LinkSample{{At: t0, Link: "isp1", State: model.LinkStateUp, RTT: time.Millisecond}}, &SystemSample{At: t0})
	_ = s.AppendEvent(ctx, event.Event{Topic: event.TopicDaemon, Time: t0})
	if err := s.Rollup(ctx, t0.Add(25*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if m, _ := s.LinkStats(ctx, "isp1", ResMinute, t0, t0.Add(time.Hour)); len(m) != 0 {
		t.Fatalf("minutes past retention must be pruned: %+v", m)
	}
	if h, _ := s.LinkStats(ctx, "isp1", ResHour, t0, t0.Add(time.Hour)); len(h) != 1 {
		t.Fatalf("hour summary must survive minute pruning: %+v", h)
	}
	if d, _ := s.SystemStats(ctx, ResDay, t0, t0.Add(24*time.Hour)); len(d) != 1 {
		t.Fatalf("day summary is counted from the first day: %+v", d)
	}
	if e, _ := s.Events(ctx, time.Time{}, 0); len(e) != 0 {
		t.Fatalf("old events must be pruned: %+v", e)
	}
	_ = s.Rollup(ctx, t0.Add(30*24*time.Hour))
	if d, _ := s.SystemStats(ctx, ResDay, t0, t0.Add(24*time.Hour)); len(d) != 0 {
		t.Fatalf("day summary past retention must be pruned: %+v", d)
	}
}

func TestFileReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "tross.db")
	s, err := Open(path, DefaultRetention())
	if err != nil {
		t.Fatal(err)
	}
	_ = s.SaveDevice(ctx, model.Device{ID: "d1"})
	if s.SizeBytes() == 0 {
		t.Fatal("file size must be reported")
	}
	_ = s.Close()
	// Повторное открытие: миграции не применяются второй раз, данные на месте.
	s, err = Open(path, DefaultRetention())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got, _ := s.Devices(ctx); len(got) != 1 {
		t.Fatalf("devices after reopen = %+v", got)
	}
}

func TestDNSDebug(t *testing.T) {
	s, err := Open("", DefaultRetention())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Now()
	old := DNSDebugRow{At: now.Add(-49 * time.Hour), Device: "192.168.1.5", Name: "old.example", Type: 1}
	fresh := DNSDebugRow{At: now, Device: "192.168.1.5", Name: "new.example", Type: 1, Cached: true, Link: "isp1"}
	if err := s.AppendDNSDebug(ctx, []DNSDebugRow{old, fresh}, 48*time.Hour); err != nil {
		t.Fatal(err)
	}
	rows, err := s.DNSDebug(ctx)
	if err != nil || len(rows) != 1 || rows[0].Name != "new.example" || !rows[0].Cached || rows[0].Link != "isp1" {
		t.Fatalf("rows %+v %v — want only the fresh one", rows, err)
	}
	if n, err := s.PurgeDNSDebug(ctx, time.Time{}); err != nil || n != 1 {
		t.Errorf("purge: %d %v", n, err)
	}
	if rows, _ := s.DNSDebug(ctx); len(rows) != 0 {
		t.Errorf("after purge: %+v", rows)
	}
}
