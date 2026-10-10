package event

import (
	"testing"
	"time"
)

func TestBusTopicFilter(t *testing.T) {
	b := NewBus()
	links, unsubLinks := b.Subscribe(4, TopicLinkState)
	all, unsubAll := b.Subscribe(4)
	defer unsubLinks()
	defer unsubAll()

	b.Publish(Event{Topic: TopicDeviceNew})
	b.Publish(Event{Topic: TopicLinkState, Data: "x"})

	if got := len(links); got != 1 {
		t.Fatalf("filtered subscriber got %d events, want 1", got)
	}
	if e := <-links; e.Topic != TopicLinkState || e.Time.IsZero() {
		t.Fatalf("unexpected event %+v", e)
	}
	if got := len(all); got != 2 {
		t.Fatalf("catch-all subscriber got %d events, want 2", got)
	}
}

func TestBusSlowSubscriberDoesNotBlock(t *testing.T) {
	b := NewBus()
	_, unsub := b.Subscribe(1)
	defer unsub()

	done := make(chan struct{})
	go func() {
		for range 10 {
			b.Publish(Event{Topic: TopicDaemon})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Publish blocked on a full subscriber")
	}
	if b.Dropped() != 9 {
		t.Fatalf("dropped = %d, want 9", b.Dropped())
	}
}

func TestBusUnsubscribeClosesChannel(t *testing.T) {
	b := NewBus()
	ch, unsub := b.Subscribe(1)
	unsub()
	unsub() // повторный вызов безопасен
	if _, ok := <-ch; ok {
		t.Fatal("channel must be closed after unsubscribe")
	}
	b.Publish(Event{Topic: TopicDaemon}) // не паникует после отписки
}
