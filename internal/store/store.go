// Package store — постоянное хранилище демона на SQLite: устройства,
// доменные правила, события и статистика (поминутно + накопительные сводки
// по часам и дням с ограниченным сроком хранения).
package store

import (
	"context"
	"errors"
	"time"

	"tross/core/event"
	"tross/core/model"
)

var ErrClosed = errors.New("store: closed")

// RuleKey однозначно определяет доменное правило.
type RuleKey struct {
	Layer   model.RuleLayer
	Match   model.MatchKind
	Pattern string
}

func KeyOf(r model.DomainRule) RuleKey {
	return RuleKey{Layer: r.Layer, Match: r.Match, Pattern: r.Pattern}
}

// LinkSample — поминутная выборка канала.
type LinkSample struct {
	At      time.Time
	Link    model.LinkID
	State   model.LinkState
	RTT     time.Duration
	Jitter  time.Duration
	Loss    float64
	RxBytes uint64 // за минуту
	TxBytes uint64
}

// SystemSample — поминутная выборка машины и самого демона.
type SystemSample struct {
	At          time.Time
	CPUBusy     float64 // % всей машины
	CPUSoftIRQ  float64 // % на обработку пакетов ядром
	MemUsedMB   float64
	ProcCPU     float64 // % одного ядра, процесс демона
	ProcRSSMB   float64
	DiskWriteKB float64 // записано на диск процессом демона за минуту
}

// Resolution — шаг статистики.
type Resolution string

const (
	ResMinute Resolution = "minute"
	ResHour   Resolution = "hour"
	ResDay    Resolution = "day"
)

func (r Resolution) Step() time.Duration {
	switch r {
	case ResHour:
		return time.Hour
	case ResDay:
		return 24 * time.Hour
	}
	return time.Minute
}

// LinkStat — строка статистики канала. Задержки — в мс; у поминутной строки
// min = avg = max = p95.
type LinkStat struct {
	At            time.Time    `json:"at"`
	Link          model.LinkID `json:"link"`
	Samples       int          `json:"samples"`
	UsableMinutes int          `json:"usable_minutes"`
	RTTMin        float64      `json:"rtt_min_ms"`
	RTTAvg        float64      `json:"rtt_avg_ms"`
	RTTMax        float64      `json:"rtt_max_ms"`
	RTTP95        float64      `json:"rtt_p95_ms"`
	JitterAvg     float64      `json:"jitter_avg_ms"`
	JitterP95     float64      `json:"jitter_p95_ms"`
	LossAvg       float64      `json:"loss_avg"`
	LossMax       float64      `json:"loss_max"`
	RxBytes       uint64       `json:"rx_bytes"`
	TxBytes       uint64       `json:"tx_bytes"`
}

// SystemStat — строка статистики машины.
type SystemStat struct {
	At          time.Time `json:"at"`
	Samples     int       `json:"samples"`
	CPUAvg      float64   `json:"cpu_avg"`
	CPUMax      float64   `json:"cpu_max"`
	CPUP95      float64   `json:"cpu_p95"`
	SoftIRQAvg  float64   `json:"softirq_avg"`
	SoftIRQMax  float64   `json:"softirq_max"`
	MemAvgMB    float64   `json:"mem_avg_mb"`
	MemMaxMB    float64   `json:"mem_max_mb"`
	ProcCPUAvg  float64   `json:"proc_cpu_avg"`
	ProcCPUMax  float64   `json:"proc_cpu_max"`
	ProcCPUP95  float64   `json:"proc_cpu_p95"`
	RSSAvgMB    float64   `json:"rss_avg_mb"`
	RSSMaxMB    float64   `json:"rss_max_mb"`
	DiskWriteKB float64   `json:"disk_write_kb"`
}

// Retention — сроки хранения (подробнее — docs/CONTEXT_storage.md).
type Retention struct {
	Minute, Hour, Day, Events time.Duration
}

func DefaultRetention() Retention {
	const day = 24 * time.Hour
	return Retention{Minute: 90 * day, Hour: 180 * day, Day: 365 * day, Events: 365 * day}
}

type Store interface {
	SaveDevice(ctx context.Context, d model.Device) error
	DeleteDevice(ctx context.Context, id string) error
	Devices(ctx context.Context) ([]model.Device, error)

	SaveRule(ctx context.Context, r model.DomainRule) error
	DeleteRule(ctx context.Context, k RuleKey) error
	Rules(ctx context.Context, layer model.RuleLayer) ([]model.DomainRule, error)

	AppendEvent(ctx context.Context, e event.Event) error
	// Events — события не раньше since, не больше limit последних, по
	// возрастанию времени; Data — исходный JSON.
	Events(ctx context.Context, since time.Time, limit int) ([]event.Event, error)

	// AppendSamples пишет поминутные выборки одной транзакцией (беречь SSD).
	AppendSamples(ctx context.Context, links []LinkSample, sys *SystemSample) error
	// Rollup считает сводки за закрытые часы и дни и удаляет данные старше
	// сроков хранения.
	Rollup(ctx context.Context, now time.Time) error
	LinkStats(ctx context.Context, link model.LinkID, res Resolution, from, to time.Time) ([]LinkStat, error)
	SystemStats(ctx context.Context, res Resolution, from, to time.Time) ([]SystemStat, error)

	// SizeBytes — размер файла базы (0 для базы в памяти).
	SizeBytes() int64
	Close() error
}
