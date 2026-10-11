package linkmon

import (
	"log/slog"
	"net/netip"
	"time"

	"tross/core/event"
	"tross/core/linkhealth"
	"tross/core/model"
)

// LinkProbe — канал и всё, что нужно для проб через него.
type LinkProbe struct {
	Link model.Link
	// Mark — fwmark канала: пробы идут по его таблице маршрутизации.
	Mark      uint32
	Targets   []netip.Addr // общие цели
	Whitelist []netip.Addr // цели белого списка; пусто — распознавание выключено
}

// HTTPCheckURL — адрес проверки подключения и ожидаемый ответ.
type HTTPCheckURL struct {
	URL    string
	Status int
	Body   string // подстрока тела; пусто — не проверять
}

// HTTPCheckOptions — проверка «настоящего» интернета через канал; пустой
// URLs — выключена.
type HTTPCheckOptions struct {
	Interval time.Duration
	Timeout  time.Duration
	DNS      []netip.Addr
	URLs     []HTTPCheckURL
}

type SpeedTestOptions struct {
	URLs         []string // по порядку: следующий — если предыдущий не отдал данных
	Hour, Minute int      // ночной замер (только нелимитированные каналы)
	Duration     time.Duration
	MaxBytes     int64
}

// Options — настройки реального монитора.
type Options struct {
	Log       *slog.Logger
	Bus       event.EventBus
	Interval  time.Duration
	Timeout   time.Duration
	Params    linkhealth.Params
	TCPPort   uint16
	HTTPCheck HTTPCheckOptions
	SpeedTest SpeedTestOptions
}

// activeValidFor — сколько учитывается результат активного замера.
const activeValidFor = 7 * 24 * time.Hour

// combineThroughput — скорость канала: пассивный пик за сутки или свежий
// активный замер, что больше (пассивный не знает предела, если канал не
// нагружали).
func combineThroughput(now time.Time, passiveDown, passiveUp uint64, active model.Throughput) model.Throughput {
	th := model.Throughput{DownBps: passiveDown, UpBps: passiveUp, MeasuredAt: now}
	if !active.MeasuredAt.IsZero() && now.Sub(active.MeasuredAt) < activeValidFor {
		th.DownBps = max(th.DownBps, active.DownBps)
		th.UpBps = max(th.UpBps, active.UpBps)
	}
	return th
}
