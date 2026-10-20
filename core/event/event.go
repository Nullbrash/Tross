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
	TopicDaemon    Topic = "daemon"
	TopicLinkState Topic = "link.state"
	TopicDeviceNew Topic = "device.new"
	// TopicDeviceSame — новая запись похожа на пропавшую (смена случайного
	// MAC): объединяет пользователь (данные — DeviceEvent).
	TopicDeviceSame Topic = "device.same"
	// TopicDHCP — раздача адресов: второй DHCP-сервер в LAN (данные —
	// DHCPEvent).
	TopicDHCP Topic = "dhcp"
	// TopicUPnP — пробросы по запросу программ: открыт, закрыт, отказ, ждёт
	// решения пользователя (данные — UPnPEvent).
	TopicUPnP        Topic = "upnp"
	TopicDNSWatchdog Topic = "dns.watchdog"
	// TopicLinkRound — каждый раунд проб монитора (данные — LinkRound):
	// живой сигнал для очередей CAKE; в журнал и историю не пишется.
	TopicLinkRound Topic = "link.round"
	// TopicSQM — смена скорости очередей канала (данные — SQMChange).
	TopicSQM Topic = "sqm"
	// TopicDNSDebug — отладочный журнал DNS включён или выключен: видно, если
	// его включил не владелец.
	TopicDNSDebug Topic = "dns.debug"
	// TopicDPI — движок обхода DPI: запуск, падение, откат, отвергнутая
	// стратегия (данные — DPIEvent).
	TopicDPI Topic = "dpi"
)

// JournalTopics — темы, которые пишутся в журнал и историю событий:
// всё, кроме частых служебных (раунды проб).
func JournalTopics() []Topic {
	return []Topic{TopicDaemon, TopicLinkState, TopicDeviceNew, TopicDeviceSame, TopicDHCP, TopicUPnP, TopicDNSWatchdog, TopicSQM, TopicDNSDebug, TopicDPI}
}

// UPnPEvent — данные события TopicUPnP; Action — open, close, refuse, ask.
type UPnPEvent struct {
	Action  string `json:"action"`
	Device  string `json:"device,omitempty"`
	Addr    string `json:"addr"`
	Proto   string `json:"proto"`
	ExtPort uint16 `json:"ext_port"`
	IntPort uint16 `json:"int_port,omitempty"`
	Desc    string `json:"desc,omitempty"`
	Via     string `json:"via,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// DHCPEvent — данные события TopicDHCP.
type DHCPEvent struct {
	Msg    string `json:"msg"`
	Server string `json:"server,omitempty"`
	MAC    string `json:"mac,omitempty"`
}

// DeviceEvent — данные событий устройств: запись и, для device.same, на
// какую запись она похожа и почему.
type DeviceEvent struct {
	ID      string           `json:"id"`
	MAC     string           `json:"mac"`
	Addr    string           `json:"addr,omitempty"`
	Name    string           `json:"name,omitempty"`
	Vendor  string           `json:"vendor,omitempty"`
	Type    model.DeviceType `json:"type"`
	SameAs  string           `json:"same_as,omitempty"`
	Reasons []string         `json:"reasons,omitempty"`
}

// DPIEvent — данные события TopicDPI; Link пуст — движок целиком.
type DPIEvent struct {
	Link model.LinkID `json:"link,omitempty"`
	Msg  string       `json:"msg"`
}

// LinkRound — данные события TopicLinkRound.
type LinkRound struct {
	Link model.LinkID `json:"link"`
	// DownBps, UpBps — трафик интерфейса канала с прошлого раунда.
	DownBps uint64 `json:"down_bps"`
	UpBps   uint64 `json:"up_bps"`
	// RTTs — задержка по целям в этом раунде (ответившие).
	RTTs map[string]time.Duration `json:"rtts"`
}

// SQMChange — данные события TopicSQM.
type SQMChange struct {
	Link    model.LinkID `json:"link"`
	DownBps uint64       `json:"down_bps"` // 0 — без ограничения
	UpBps   uint64       `json:"up_bps"`
	Reason  string       `json:"reason"`
}

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
