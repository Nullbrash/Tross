package daemon

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	coredpi "tross/core/dpi"
	"tross/core/event"
	"tross/core/model"
	"tross/internal/dataplane"
	"tross/internal/dpi"
	"tross/internal/store"
)

// okRunner — движок, который принимает всё и живёт до остановки.
type okRunner struct{ starts int }

func (r *okRunner) Output(context.Context, string, []string) ([]byte, error) { return nil, nil }
func (r *okRunner) Start(string, []string, io.Writer) (dpi.Process, error) {
	r.starts++
	return &okProc{done: make(chan struct{})}, nil
}

type okProc struct{ done chan struct{} }

func (p *okProc) Wait() error { <-p.done; return nil }
func (p *okProc) Stop() error {
	select {
	case <-p.done:
	default:
		close(p.done)
	}
	return nil
}

func dpiBench(t *testing.T, manual []model.DomainRule) (*dpiService, dpi.Engine, *store.SQLite) {
	t.Helper()
	st, err := store.Open("", store.DefaultRetention())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cat, _ := coredpi.Builtin()
	eng := dpi.Engine{Binary: "/opt/zapret2/nfqws2", LuaDir: "/opt/zapret2/lua", Dir: t.TempDir()}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &dpiService{log: log, bus: event.NewBus(), st: st, dp: dataplane.NewFake(log), cat: cat,
		manual: func() []model.DomainRule { return manual },
		links:  map[model.LinkID]int{"isp1": 0, "isp2": 1}, verdicts: map[string]map[model.LinkID]coredpi.Verdict{},
		strategy: map[model.LinkID]*coredpi.Strategy{}, used: map[string]time.Time{}}
	s.mgr = dpi.NewManager(eng, &okRunner{}, []dpi.LinkConfig{{Link: "isp1", Queue: 200}, {Link: "isp2", Queue: 201}}, nil)
	return s, eng, st
}

var netip0 = netip.MustParseAddr("192.168.10.30")

func verdict(key string, link model.LinkID, m coredpi.Method, strat string) store.DPIVerdict {
	return store.DPIVerdict{Key: key, Link: link, Verdict: coredpi.Verdict{Method: m, Strategy: strat, CheckedAt: time.Now()}}
}

// Адрес — в множество обхода только тех каналов, где домену обход нужен и
// у движка канала есть стратегия; ручное правило — на всех таких каналах.
func TestDPIBypassSets(t *testing.T) {
	ctx := context.Background()
	s, eng, st := dpiBench(t, []model.DomainRule{{Pattern: "mine.example", Match: model.MatchSuffix, Layer: model.LayerManual, Purpose: model.PurposeBypass}})
	if err := s.setVerdicts(ctx, []store.DPIVerdict{
		verdict("blocked.example", "isp1", coredpi.MethodDPI, "split-1-midsld"),
		verdict("blocked.example", "isp2", coredpi.MethodDirect, ""),
	}); err != nil {
		t.Fatal(err)
	}
	// Стратегий ещё нет — обхода нет нигде.
	if got := s.bypass("blocked.example", model.LayerOnline, "www.blocked.example", netip0); len(got) != 0 {
		t.Fatalf("no strategy yet, sets %v", got)
	}
	for _, l := range []model.LinkID{"isp1", "isp2"} {
		if err := s.setScores(ctx, l, []coredpi.Score{{Strategy: "disorder-1-midsld", Opened: 2}, {Strategy: "split-1-midsld", Opened: 3}, {Strategy: "wssize-1", Opened: 9}}); err != nil {
			t.Fatal(err)
		}
	}
	if got := s.bypass("blocked.example", model.LayerOnline, "www.blocked.example", netip0); !slices.Equal(got, []dataplane.SetName{"tross_dpi0"}) {
		t.Errorf("verdict sets %v, want only isp1", got)
	}
	if got := s.bypass("mine.example", model.LayerManual, "mine.example", netip0); !slices.Equal(got, []dataplane.SetName{"tross_dpi0", "tross_dpi1"}) {
		t.Errorf("manual rule sets %v, want both links", got)
	}
	if got := s.bypass("unknown.example", model.LayerOnline, "unknown.example", netip0); len(got) != 0 {
		t.Errorf("unchecked domain got bypass: %v", got)
	}
	// Лучшая разрешённая стратегия: wssize рискованна и не подбирается.
	if st := s.mgr.Status(); st[0].Strategy != "split-1-midsld" || st[1].Strategy != "split-1-midsld" {
		t.Errorf("engine strategies %+v", st)
	}
	b, _ := os.ReadFile(eng.HostlistPath("isp1"))
	if string(b) != "blocked.example\nmine.example\n" {
		t.Errorf("isp1 hostlist %q", b)
	}
	b, _ = os.ReadFile(eng.HostlistPath("isp2"))
	if string(b) != "mine.example\n" {
		t.Errorf("isp2 hostlist %q", b)
	}
	// Отметки «спрашивали» — пачкой, только для известных решений.
	s.flushUsed(ctx)
	vs, _ := st.DPIVerdicts(ctx)
	for _, v := range vs {
		if v.Key == "blocked.example" && v.UsedAt.IsZero() {
			t.Errorf("usage not saved: %+v", v)
		}
	}
	// Перезапуск: решения и стратегия — из базы.
	s2, _, _ := dpiBench(t, nil)
	s2.st = st
	if err := s2.load(ctx); err != nil {
		t.Fatal(err)
	}
	if got := s2.bypass("blocked.example", model.LayerOnline, "blocked.example", netip0); !slices.Equal(got, []dataplane.SetName{"tross_dpi0"}) || s2.strategy["isp1"].ID != "split-1-midsld" {
		t.Errorf("after restart: sets %v, strategy %+v", got, s2.strategy["isp1"])
	}
	var nilSvc *dpiService
	if nilSvc.bypass("x", model.LayerManual, "x", netip0) != nil || nilSvc.status() != nil {
		t.Error("disabled service must do nothing")
	}
}
