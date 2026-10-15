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

var ErrUnsupportedOS = errors.New("dataplane: kernel mode is supported only on linux; use dry-run")

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
	Links        []LinkSpec
	// Classify — классы и правила классификации; пусто — один класс default.
	Classify Classify
	// Forwards — ручные пробросы портов; Guard — их общая защита.
	Forwards []PortForward
	Guard    InboundGuard
}

// Dataplane — всё, что демон меняет в сетевом стеке ядра.
// Teardown обязан снимать всё, что поставил Setup, кроме NAT: при остановке
// демона сеть должна откатиться в работоспособное состояние без него —
// через основную таблицу маршрутизации и оставшийся masquerade.
type Dataplane interface {
	Setup(ctx context.Context, spec Spec) error
	Teardown(ctx context.Context) error
	// SetBalance задаёт распределение новых соединений из домашней сети по
	// каналам (вес > 0); пусто — ни одного пригодного канала. Установленные
	// соединения не переезжают.
	SetBalance(ctx context.Context, shares []decision.LinkShare) error
	// SetPlan задаёт распределение и закрепления по классам (Engine.Plan);
	// классы, которых нет в плане, сохраняют прежнее.
	SetPlan(ctx context.Context, plan []decision.ClassPlan) error
	// AddToSet кладёт адрес в множество с таймаутом (обычно — по TTL DNS-ответа).
	AddToSet(ctx context.Context, set SetName, addr netip.Addr, ttl time.Duration) error
	// FlushConntrack сбрасывает соединения, закреплённые за упавшим каналом.
	FlushConntrack(ctx context.Context, id model.LinkID) error
	// RepairRoutes ставит заново маршруты таблиц каналов, если их нет или
	// сменился шлюз из DHCP: ядро удаляет маршрут вместе с пересозданным или
	// выключенным интерфейсом, и без этого канал не вернулся бы до перезапуска.
	RepairRoutes(ctx context.Context) error
	// Connections — снимок размеченных соединений conntrack (только IPv4).
	Connections(ctx context.Context) ([]Connection, error)
	// Pins — действующие закрепления из множеств ядра.
	Pins(ctx context.Context) ([]Pin, error)
}
