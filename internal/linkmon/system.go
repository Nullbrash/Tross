package linkmon

import (
	"crypto/x509"
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
	Status int    // 0 — любой ответ (только для Domestic по https)
	Body   string // подстрока тела; пусто — не проверять
	// Domestic — российский адрес: не засчитывается как «интернет есть»,
	// а уточняет причину неудачи (нет зарубежного / нет HTTP вовсе).
	Domestic bool
}

// HTTPCheckOptions — проверка «настоящего» интернета через канал; пустой
// URLs — выключена.
type HTTPCheckOptions struct {
	Interval time.Duration
	Timeout  time.Duration
	DNS      []DNSServer
	URLs     []HTTPCheckURL
	RootCAs  *x509.CertPool // корни для DoT/DoH; nil — системные (свои — для стенда)
}

type SpeedTestOptions struct {
	URLs         []string // по порядку: следующий — если передача застыла или источник отдал заглушку
	Hour, Minute int      // ночной замер (только нелимитированные каналы)
	Duration     time.Duration
	MaxBytes     int64
}

// Options — настройки реального монитора.
type Options struct {
	Log      *slog.Logger
	Bus      event.EventBus
	Interval time.Duration
	Timeout  time.Duration
	Params   linkhealth.Params
	// TCPTargets — по одной TCP-пробе за раунд, по кругу.
	TCPTargets []netip.AddrPort
	HTTPCheck  HTTPCheckOptions
	SpeedTest  SpeedTestOptions
	// SpeedTestHook вызывается перед активным замером канала; возвращённая
	// функция — после него с результатом. Очереди CAKE на это время снимают
	// ограничение, иначе тест измерил бы саму очередь, а не канал. nil — нет.
	SpeedTestHook func(id model.LinkID) func(model.Throughput, error)
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
