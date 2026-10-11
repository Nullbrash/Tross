// Package dataplane управляет правилами ядра Linux: nftables (разметка
// fwmark, множества адресов, перехват DNS, NFQUEUE для zapret, tproxy для
// прокси), ip rule и отдельные таблицы маршрутизации каналов, conntrack, tc.
// Сам демон пакеты не пересылает.
//
// Реальная реализация — только под Linux (system_linux.go); для «сухого»
// режима и тестов — Fake.
package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"tross/core/decision"
	"tross/core/model"
)

var (
	ErrNotImplemented = errors.New("dataplane: not implemented yet")
	ErrUnsupportedOS  = errors.New("dataplane: kernel mode is supported only on linux; use dry-run")
)

// SetName — имя множества адресов nftables, наполняемого резолвером.
type SetName string

const (
	SetDPI   SetName = "tross_dpi4"
	SetProxy SetName = "tross_proxy4"
)

// LinkSpec — канал вместе с его ресурсами в ядре.
type LinkSpec struct {
	Link    model.Link
	Table   int
	FwMark  uint32
	Gateway netip.Addr // невалидный адрес — шлюз берётся из DHCP
}

// Spec — базовая разметка, которую демон ставит при старте.
type Spec struct {
	LANInterface string
	LANNetworks  []netip.Prefix
	Links        []LinkSpec
}

// Dataplane — всё, что демон меняет в сетевом стеке ядра.
// Teardown обязан снимать всё, что поставил Setup: при остановке демона сеть
// должна откатиться в работоспособное состояние без него.
type Dataplane interface {
	Setup(ctx context.Context, spec Spec) error
	Teardown(ctx context.Context) error
	// SetBalance задаёт распределение новых соединений из домашней сети по
	// каналам (вес > 0); пусто — ни одного пригодного канала. Установленные
	// соединения не переезжают.
	SetBalance(ctx context.Context, shares []decision.LinkShare) error
	// AddToSet кладёт адрес в множество с таймаутом (обычно — по TTL DNS-ответа).
	AddToSet(ctx context.Context, set SetName, addr netip.Addr, ttl time.Duration) error
	// FlushConntrack сбрасывает соединения, закреплённые за упавшим каналом.
	FlushConntrack(ctx context.Context, id model.LinkID) error
}
