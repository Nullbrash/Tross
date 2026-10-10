package linkmon

import (
	"testing"
	"time"

	"tross/core/event"
	"tross/core/model"
)

func testLinks() []model.Link {
	return []model.Link{
		{ID: "isp1", Kind: model.LinkKindWired, Interface: "enp2s0"},
		{ID: "lte", Kind: model.LinkKindLTE, Interface: "enp4s0", Metered: true},
	}
}

func TestFakeTickProducesValidHealth(t *testing.T) {
	bus := event.NewBus()
	ch, unsub := bus.Subscribe(8, event.TopicLinkState)
	defer unsub()

	f := NewFake(testLinks(), bus, time.Second, 1)
	f.Tick()

	snap := f.Snapshot()
	if len(snap) != 2 || snap[0].Link.ID != "isp1" || snap[1].Link.ID != "lte" {
		t.Fatalf("snapshot order/content wrong: %+v", snap)
	}
	for _, s := range snap {
		if err := s.Health.Validate(); err != nil {
			t.Errorf("%s: invalid health: %v", s.Link.ID, err)
		}
		if s.Health.State != model.LinkStateUp {
			t.Errorf("%s: state %s, want up", s.Link.ID, s.Health.State)
		}
	}
	if snap[1].Health.RTT <= snap[0].Health.RTT {
		t.Errorf("fake LTE should have higher RTT than wired")
	}
	if len(ch) != 2 {
		t.Fatalf("got %d state events after first tick, want 2", len(ch))
	}

	f.Tick()
	if len(ch) != 2 {
		t.Fatal("no new events expected while states are unchanged")
	}
}

func TestFakeForceState(t *testing.T) {
	bus := event.NewBus()
	f := NewFake(testLinks(), bus, time.Second, 1)
	f.Tick()

	ch, unsub := bus.Subscribe(8, event.TopicLinkState)
	defer unsub()
	f.ForceState("isp1", model.LinkStateDown)
	f.Tick()

	st, ok := f.Status("isp1")
	if !ok || st.Health.State != model.LinkStateDown || st.Health.Loss != 1 {
		t.Fatalf("forced down not applied: %+v", st)
	}
	e := <-ch
	c := e.Data.(event.LinkStateChange)
	if c.Link != "isp1" || c.From != model.LinkStateUp || c.To != model.LinkStateDown {
		t.Fatalf("unexpected change event %+v", c)
	}
	if _, ok := f.Status("nope"); ok {
		t.Fatal("unknown link must not be found")
	}
}
