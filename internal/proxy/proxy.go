// Package proxy — адаптер прокси-ядра (этап 6). Первая реализация — mihomo
// отдельным процессом; интерфейс тонкий, чтобы ядро можно было заменить
// (например, на sing-box).
package proxy

import (
	"context"
	"time"

	"tross/core/model"
)

// Binding — прокси-выход вместе с ресурсами, выделенными ему демоном:
// свой tproxy-порт (куда dataplane направляет соединения) и свой
// routing-mark (по нему ip rule выбирает канал для трафика самого прокси).
type Binding struct {
	Outbound    model.ProxyOutbound
	TProxyPort  uint16
	RoutingMark uint32
}

type OutboundStatus struct {
	ID        string        `json:"id"`
	Name      string        `json:"name"`
	Alive     bool          `json:"alive"`
	Latency   time.Duration `json:"latency"`
	CheckedAt time.Time     `json:"checked_at"`
}

// ProxyCore генерирует конфиг ядра, запускает и сторожит процесс, даёт доступ
// к его API (только 127.0.0.1, с секретом).
type ProxyCore interface {
	// Run запускает ядро и перезапускает его при падении до отмены ctx.
	Run(ctx context.Context) error
	// Apply пересобирает конфиг из набора выходов и применяет его.
	Apply(ctx context.Context, bindings []Binding) error
	Outbounds() []OutboundStatus
	Check(ctx context.Context, id string) (OutboundStatus, error)
	// CloseConnections принудительно закрывает соединения прокси,
	// ушедшие через указанный канал (при его падении).
	CloseConnections(ctx context.Context, link model.LinkID) error
}
