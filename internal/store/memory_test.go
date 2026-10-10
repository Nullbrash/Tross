package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"tross/core/event"
	"tross/core/model"
)

func TestMemoryRulesByLayer(t *testing.T) {
	ctx := context.Background()
	s := NewMemory(10)
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
	got, _ := s.Rules(ctx, model.LayerManual)
	if len(got) != 2 || got[0].Pattern != "a.com" {
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

func TestMemoryEventsRingAndFilter(t *testing.T) {
	ctx := context.Background()
	s := NewMemory(3)
	base := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	for i := range 5 {
		_ = s.AppendEvent(ctx, event.Event{Topic: event.TopicDaemon, Time: base.Add(time.Duration(i) * time.Minute)})
	}
	all, _ := s.Events(ctx, time.Time{}, 0)
	if len(all) != 3 || !all[0].Time.Equal(base.Add(2*time.Minute)) {
		t.Fatalf("ring must keep the 3 newest events, got %+v", all)
	}
	last, _ := s.Events(ctx, base.Add(3*time.Minute), 1)
	if len(last) != 1 || !last[0].Time.Equal(base.Add(4*time.Minute)) {
		t.Fatalf("since+limit = %+v", last)
	}
}

func TestMemoryClosed(t *testing.T) {
	s := NewMemory(1)
	_ = s.Close()
	if err := s.SaveDevice(context.Background(), model.Device{ID: "x"}); !errors.Is(err, ErrClosed) {
		t.Fatalf("SaveDevice after close = %v, want ErrClosed", err)
	}
	if _, err := s.Devices(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("Devices after close = %v, want ErrClosed", err)
	}
}
