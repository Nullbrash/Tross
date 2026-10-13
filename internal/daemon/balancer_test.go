package daemon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"tross/core/decision"
	"tross/core/event"
	"tross/core/model"
	"tross/internal/dataplane"
	"tross/internal/linkmon"
)

func TestBalancerFollowsMonitorAndFlushes(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	bus := event.NewBus()
	links := []model.Link{
		{ID: "isp1", Kind: model.LinkKindWired, Priority: 10},
		{ID: "isp2", Kind: model.LinkKindWired, Priority: 20},
		{ID: "lte", Kind: model.LinkKindLTE, Priority: 100},
	}
	mon := linkmon.NewFake(links, bus, time.Hour, 1)
	dp := dataplane.NewFake(log)
	b := &balancer{log: log, dp: dp, mon: mon, policy: model.Policy{
		Selector: model.SelectOrdered, Links: []model.LinkID{"isp1", "isp2"}, Fallback: []model.LinkID{"lte"},
	}}
	ctx := context.Background()

	b.apply(ctx) // все unknown — ничего не трогать
	if len(dp.Ops()) != 0 {
		t.Fatalf("balancer acted before the first monitor round: %v", dp.Ops())
	}
	mon.Tick()
	b.apply(ctx)
	mon.ForceState("isp1", model.LinkStateDown)
	mon.Tick()
	b.apply(ctx)
	mon.ForceState("isp2", model.LinkStateRestricted)
	mon.Tick()
	b.apply(ctx)
	b.apply(ctx) // без изменений — без новых вызовов

	ops := dp.Ops()
	want := []string{
		"set-balance [[{isp1 1}]]",
		"set-balance [[{isp2 1}]]",
		"flush-conntrack [isp1]",
		"set-balance [[{lte 1}]]",
		"flush-conntrack [isp2]",
	}
	if !slices.Equal(ops, want) {
		t.Fatalf("ops:\n%s\nwant:\n%s", strings.Join(ops, "\n"), strings.Join(want, "\n"))
	}
}

// failingBalance — dataplane, у которого не применяется распределение.
type failingBalance struct{ *dataplane.Fake }

func (failingBalance) SetBalance(context.Context, []decision.LinkShare) error {
	return errors.New("nft: busy")
}

func TestBalancerFlushesEvenIfBalanceFails(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	links := []model.Link{{ID: "isp1", Kind: model.LinkKindWired}, {ID: "isp2", Kind: model.LinkKindWired}}
	mon := linkmon.NewFake(links, event.NewBus(), time.Hour, 1)
	dp := failingBalance{dataplane.NewFake(log)}
	b := &balancer{log: log, dp: dp, mon: mon, policy: model.Policy{Selector: model.SelectOrdered}}
	ctx := context.Background()

	mon.Tick()
	b.apply(ctx)
	mon.ForceState("isp1", model.LinkStateDown)
	mon.Tick()
	b.apply(ctx)
	// Распределение не применилось, но соединения упавшего канала сброшены —
	// иначе застрявшие потоки ждали бы, пока ошибка пройдёт.
	if ops := dp.Ops(); !slices.Equal(ops, []string{"flush-conntrack [isp1]"}) {
		t.Fatalf("ops = %v", ops)
	}
}

// countingRepair — dataplane, считающий сверки маршрутов.
type countingRepair struct {
	*dataplane.Fake
	repairs int
}

func (c *countingRepair) RepairRoutes(context.Context) error {
	c.repairs++
	return nil
}

func TestBalancerTickRepairsRoutes(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	mon := linkmon.NewFake([]model.Link{{ID: "isp1", Kind: model.LinkKindWired}}, event.NewBus(), time.Hour, 1)
	dp := &countingRepair{Fake: dataplane.NewFake(log)}
	b := &balancer{log: log, dp: dp, mon: mon, policy: model.Policy{Selector: model.SelectOrdered}}
	mon.Tick()
	b.tick(context.Background())
	if dp.repairs != 1 || len(dp.Ops()) != 1 {
		t.Fatalf("tick must repair routes and rebalance: repairs %d, ops %v", dp.repairs, dp.Ops())
	}
}
