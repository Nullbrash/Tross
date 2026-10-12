package daemon

import (
	"context"
	"log/slog"
	"time"

	"tross/core/model"
	"tross/internal/linkmon"
	"tross/internal/sdnotify"
)

// watchdog подтверждает systemd живость, только пока монитор делает раунды:
// зависший монитор (или весь процесс) перестаёт подтверждать, и systemd
// перезапускает демон по WatchdogSec.
func watchdog(ctx context.Context, log *slog.Logger, every time.Duration, mon linkmon.LinkMonitor, interval time.Duration) {
	started := time.Now()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if monitorAlive(mon.Snapshot(), now, started, interval) {
				_ = sdnotify.Notify("WATCHDOG=1")
			} else {
				log.Warn("watchdog: link monitor stalled, not confirming liveness")
			}
		}
	}
}

// monitorAlive — хотя бы один канал обновлялся недавно; до первых раундов
// после старта монитор считается живым.
func monitorAlive(snap []model.LinkStatus, now, started time.Time, interval time.Duration) bool {
	limit := max(3*interval, 10*time.Second)
	if now.Sub(started) < limit || len(snap) == 0 {
		return true
	}
	for _, s := range snap {
		if now.Sub(s.Health.UpdatedAt) < limit {
			return true
		}
	}
	return false
}
