// Package resolver — DNS-резолвер сети (этап 4). Наружу — DoH/DoT с
// балансировкой по каналам. Для домена из списков IP попадает в множество
// nftables ДО ответа клиенту: иначе первое соединение клиента уйдёт мимо
// нужного метода.
package resolver

import (
	"context"
	"time"
)

type Stats struct {
	Queries     uint64        `json:"queries"`
	CacheHits   uint64        `json:"cache_hits"`
	Failures    uint64        `json:"failures"`
	AvgUpstream time.Duration `json:"avg_upstream"`
}

// Resolver обслуживает DNS-запросы клиентов.
type Resolver interface {
	// Run слушает адреса из конфигурации до отмены ctx.
	Run(ctx context.Context) error
	// Healthy используется сторожем: при false перехват DNS снимается
	// и клиенты временно ходят к DNS напрямую.
	Healthy() bool
	Stats() Stats
}
