//go:build linux

package dataplane

import (
	"context"
	"log/slog"
	"net/netip"
	"time"

	"tross/core/model"
)

// System — реализация через nftables/netlink (этап 1). Пока — заготовка.
type System struct {
	log *slog.Logger
}

var _ Dataplane = (*System)(nil)

func NewSystem(log *slog.Logger) (Dataplane, error) { return &System{log: log}, nil }

func (s *System) Setup(context.Context, Spec) error { return ErrNotImplemented }

func (s *System) Teardown(context.Context) error { return nil }

func (s *System) SetLinkUsable(context.Context, model.LinkID, bool) error {
	return ErrNotImplemented
}

func (s *System) AddToSet(context.Context, SetName, netip.Addr, time.Duration) error {
	return ErrNotImplemented
}

func (s *System) FlushConntrack(context.Context, model.LinkID) error { return ErrNotImplemented }
