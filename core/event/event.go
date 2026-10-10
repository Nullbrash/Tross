// Package event — шина событий между модулями (смена состояния каналов,
// новые устройства, срабатывание сторожа DNS и т.п.).
package event

import (
	"sync"
	"sync/atomic"
	"time"

	"tross/core/model"
)

type Topic string

const (
	TopicDaemon      Topic = "daemon"
	TopicLinkState   Topic = "link.state"
	TopicDeviceNew   Topic = "device.new"
	TopicDNSWatchdog Topic = "dns.watchdog"
)

type Event struct {
	Topic Topic     `json:"topic"`
	Time  time.Time `json:"time"`
	Data  any       `json:"data,omitempty"`
}

// LinkStateChange — данные события TopicLinkState.
type LinkStateChange struct {
	Link   model.LinkID    `json:"link"`
	From   model.LinkState `json:"from"`
	To     model.LinkState `json:"to"`
	Reason string          `json:"reason,omitempty"`
}

// EventBus — публикация и подписка на события.
type EventBus interface {
	Publish(e Event)
	// Subscribe возвращает канал событий указанных тем (без тем — все)
	// и функцию отписки, закрывающую канал. Медленный подписчик не блокирует
	// публикацию: не поместившиеся в буфер события для него теряются.
	Subscribe(buffer int, topics ...Topic) (<-chan Event, func())
}

// Bus — реализация EventBus в памяти процесса.
type Bus struct {
	mu      sync.RWMutex
	subs    map[*subscriber]struct{}
	dropped atomic.Uint64
}

type subscriber struct {
	ch     chan Event
	topics map[Topic]bool
}

func NewBus() *Bus { return &Bus{subs: make(map[*subscriber]struct{})} }

func (b *Bus) Publish(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	// Отправка под RLock: отписка берёт Lock перед close, поэтому
	// запись в закрытый канал невозможна.
	b.mu.RLock()
	defer b.mu.RUnlock()
	for s := range b.subs {
		if len(s.topics) > 0 && !s.topics[e.Topic] {
			continue
		}
		select {
		case s.ch <- e:
		default:
			b.dropped.Add(1)
		}
	}
}

func (b *Bus) Subscribe(buffer int, topics ...Topic) (<-chan Event, func()) {
	s := &subscriber{ch: make(chan Event, max(buffer, 0))}
	if len(topics) > 0 {
		s.topics = make(map[Topic]bool, len(topics))
		for _, t := range topics {
			s.topics[t] = true
		}
	}
	b.mu.Lock()
	b.subs[s] = struct{}{}
	b.mu.Unlock()
	return s.ch, sync.OnceFunc(func() {
		b.mu.Lock()
		delete(b.subs, s)
		close(s.ch)
		b.mu.Unlock()
	})
}

// Dropped — сколько событий потеряно из-за переполненных буферов подписчиков.
func (b *Bus) Dropped() uint64 { return b.dropped.Load() }
