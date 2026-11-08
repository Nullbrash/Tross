package api

import (
	"context"
	"net/netip"
	"time"

	"tross/core/model"
)

// TemporaryForwards — краткоживущие TCP-пробросы. Они намеренно не
// переживают перезапуск: после сбоя доступ не должен остаться открыт.
type TemporaryForwards interface {
	ListTemporaryForwards(ctx context.Context) ([]TemporaryForward, error)
	OpenTemporaryForward(ctx context.Context, req TemporaryForwardRequest) (TemporaryForward, error)
	CloseTemporaryForward(ctx context.Context, id string) error
}

type TemporaryForwardRequest struct {
	Name   string         `json:"name"`
	Port   uint16         `json:"port"`
	To     netip.Addr     `json:"to"`
	ToPort uint16         `json:"to_port"`
	Links  []model.LinkID `json:"links"`
}

type TemporaryForward struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Port        uint16         `json:"port"`
	To          netip.Addr     `json:"to"`
	ToPort      uint16         `json:"to_port"`
	Links       []model.LinkID `json:"links,omitempty"`
	OpenedAt    time.Time      `json:"opened_at"`
	LastInbound time.Time      `json:"last_inbound"`
	ExpiresAt   time.Time      `json:"expires_at"`
}
