package daemon

import (
	"testing"
	"time"

	"tross/core/model"
)

func TestMonitorAlive(t *testing.T) {
	t0 := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	iv := 2 * time.Second
	snap := func(ago time.Duration) []model.LinkStatus {
		return []model.LinkStatus{{Health: model.LinkHealth{UpdatedAt: t0.Add(-ago)}}}
	}
	started := t0.Add(-time.Hour)
	if !monitorAlive(snap(time.Second), t0, started, iv) {
		t.Error("fresh round must count as alive")
	}
	if monitorAlive(snap(time.Minute), t0, started, iv) {
		t.Error("no rounds for a minute must count as stalled")
	}
	if !monitorAlive(snap(time.Minute), t0, t0.Add(-time.Second), iv) {
		t.Error("right after start the monitor gets a grace period")
	}
	if !monitorAlive(nil, t0, started, iv) {
		t.Error("no links — nothing to watch")
	}
}
