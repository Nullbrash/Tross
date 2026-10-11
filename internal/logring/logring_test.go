package logring

import (
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"
)

func TestRingKeepsNewest(t *testing.T) {
	r := New(3)
	log := slog.New(r.Wrap(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug})))
	for i := range 5 {
		log.Info("m", "i", i)
	}
	got := r.Entries(slog.LevelDebug, 0)
	if len(got) != 3 || got[0].Attrs["i"] != int64(2) || got[2].Attrs["i"] != int64(4) {
		t.Fatalf("entries = %+v", got)
	}
	if last := r.Entries(slog.LevelDebug, 1); len(last) != 1 || last[0].Attrs["i"] != int64(4) {
		t.Fatalf("limit must keep the newest: %+v", last)
	}
}

func TestRingLevelsAndAttrs(t *testing.T) {
	r := New(10)
	log := slog.New(r.Wrap(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo})))
	log.Debug("hidden")
	log.With("mod", "linkmon").WithGroup("probe").Warn("slow", "link", "isp1", "err", errors.New("timeout"), "rtt", 5*time.Millisecond)
	log.Info("plain")

	all := r.Entries(slog.LevelDebug, 0)
	if len(all) != 2 {
		t.Fatalf("debug must be filtered like in the main log: %+v", all)
	}
	w := r.Entries(slog.LevelWarn, 0)
	if len(w) != 1 || w[0].Level != "WARN" || w[0].Msg != "slow" {
		t.Fatalf("warn = %+v", w)
	}
	a := w[0].Attrs
	if a["mod"] != "linkmon" || a["probe.link"] != "isp1" || a["probe.err"] != "timeout" || a["probe.rtt"] != "5ms" {
		t.Fatalf("attrs = %+v", a)
	}
}
