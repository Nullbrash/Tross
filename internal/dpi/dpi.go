// Package dpi — обход DPI через zapret (nfqws), этап 5. На каждый канал —
// свой экземпляр nfqws, своя очередь NFQUEUE и своя стратегия, подобранная
// автоматически (аналог blockcheck) и периодически перепроверяемая. Обход
// действует только для доменов из списка (--hostlist).
package dpi

import (
	"context"
	"time"

	"tross/core/model"
)

// Strategy — набор аргументов nfqws, проверенный на конкретном канале.
type Strategy struct {
	ID       string    `json:"id"`
	Args     []string  `json:"args"`
	TestedAt time.Time `json:"tested_at"`
}

// ProbeResult — итог проверки домена через канал.
type ProbeResult struct {
	Link    model.LinkID `json:"link"`
	Domain  string       `json:"domain"`
	Blocked bool         `json:"blocked"` // недоступен напрямую
	// Strategy — стратегия, с которой домен открылся; nil — не помогла ни одна.
	Strategy *Strategy `json:"strategy,omitempty"`
}

// DPIBypass управляет экземплярами nfqws и подбором стратегий.
type DPIBypass interface {
	// Run запускает и сторожит экземпляры nfqws до отмены ctx.
	Run(ctx context.Context) error
	Strategy(link model.LinkID) (Strategy, bool)
	// Probe проверяет доступность домена через канал напрямую и с обходом.
	Probe(ctx context.Context, link model.LinkID, domain string) (ProbeResult, error)
	// SetHostlist заменяет список доменов, к которым применяется обход на канале.
	SetHostlist(link model.LinkID, domains []string) error
}
