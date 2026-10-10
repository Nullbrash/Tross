// Package store — постоянное хранилище: конфигурация, заданная через
// интерфейс, устройства, правила, события. Основная реализация — SQLite
// (этап 1+); Memory — для «сухого» режима и тестов.
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

type Store interface {
	SaveDevice(ctx context.Context, d model.Device) error
	DeleteDevice(ctx context.Context, id string) error
	Devices(ctx context.Context) ([]model.Device, error)

	SaveRule(ctx context.Context, r model.DomainRule) error
	DeleteRule(ctx context.Context, k RuleKey) error
	Rules(ctx context.Context, layer model.RuleLayer) ([]model.DomainRule, error)

	AppendEvent(ctx context.Context, e event.Event) error
	// Events — события не раньше since, не больше limit последних, по возрастанию времени.
	Events(ctx context.Context, since time.Time, limit int) ([]event.Event, error)

	Close() error
}
