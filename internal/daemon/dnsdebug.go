package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"tross/core/event"
	"tross/internal/control"
	"tross/internal/resolver"
	"tross/internal/store"
)

const (
	// debugKeep — записи отладочного журнала живут столько, потом удаляются.
	debugKeep = 48 * time.Hour
	// debugDefault, debugMax — срок прогона по умолчанию и наибольший.
	debugDefault = 2 * time.Hour
	debugMax     = 24 * time.Hour
)

// dnsDebug — отладочный журнал DNS: имена по устройствам пишутся только во
// время прогона, включённого командой root на мини-ПК; без прогона имён
// нигде нет. Перезапуск демона прогон выключает.
type dnsDebug struct {
	log *slog.Logger
	st  store.Store
	res *resolver.Resolver // nil — резолвера нет (сухой режим)
	bus event.EventBus

	mu    sync.Mutex
	until time.Time
	timer *time.Timer
	rows  chan store.DNSDebugRow
}

func newDNSDebug(log *slog.Logger, st store.Store, res *resolver.Resolver, bus event.EventBus) *dnsDebug {
	return &dnsDebug{log: log, st: st, res: res, bus: bus, rows: make(chan store.DNSDebugRow, 1024)}
}

// DNSDebugStatus — для API: идёт ли прогон.
type DNSDebugStatus struct {
	Active bool      `json:"active"`
	Until  time.Time `json:"until,omitzero"`
}

func (d *dnsDebug) status() DNSDebugStatus {
	d.mu.Lock()
	defer d.mu.Unlock()
	return DNSDebugStatus{Active: !d.until.IsZero(), Until: d.until}
}

func (d *dnsDebug) start(dur time.Duration) (DNSDebugStatus, error) {
	if d.res == nil {
		return DNSDebugStatus{}, errors.New("resolver is not running (dry run)")
	}
	if dur == 0 {
		dur = debugDefault
	}
	if dur < 0 || dur > debugMax {
		return DNSDebugStatus{}, fmt.Errorf("duration must be within 0..%v", debugMax)
	}
	d.mu.Lock()
	d.until = time.Now().Add(dur)
	if d.timer != nil {
		d.timer.Stop()
	}
	d.timer = time.AfterFunc(dur, func() { d.stop("time is up") })
	until := d.until
	d.mu.Unlock()
	d.res.SetQueryLog(d.add)
	d.publish(fmt.Sprintf("dns debug log ON until %s", until.Format(time.RFC3339)))
	return d.status(), nil
}

func (d *dnsDebug) stop(why string) {
	d.mu.Lock()
	was := !d.until.IsZero()
	d.until = time.Time{}
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	d.mu.Unlock()
	if d.res != nil {
		d.res.SetQueryLog(nil)
	}
	if was {
		d.publish("dns debug log OFF: " + why)
	}
}

func (d *dnsDebug) publish(msg string) {
	d.log.Warn(msg)
	d.bus.Publish(event.Event{Topic: event.TopicDNSDebug, Data: msg})
}

func (d *dnsDebug) add(q resolver.QueryLog) {
	select {
	case d.rows <- store.DNSDebugRow{At: q.At, Device: q.Client.String(), Name: q.Name, Type: q.Type, RCode: q.RCode, Cached: q.Cached, Link: q.Link}:
	default:
		// Запись в базу отстала: отладка теряет строки, а не тормозит DNS.
	}
}

// run — запись пачками и удаление старше debugKeep до отмены ctx; при
// остановке прогон выключается.
func (d *dnsDebug) run(ctx context.Context) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	prune := time.NewTicker(time.Hour)
	defer prune.Stop()
	var batch []store.DNSDebugRow
	flush := func() {
		if len(batch) == 0 {
			return
		}
		wctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := d.st.AppendDNSDebug(wctx, batch, debugKeep); err != nil {
			d.log.Warn("dns debug log: write failed", "err", err)
		}
		cancel()
		batch = batch[:0]
	}
	// Записи прошлых прогонов старше срока — и после долгого простоя.
	if _, err := d.st.PurgeDNSDebug(ctx, time.Now().Add(-debugKeep)); err != nil {
		d.log.Warn("dns debug log: prune failed", "err", err)
	}
	for {
		select {
		case <-ctx.Done():
			d.stop("daemon stopping")
			for {
				select {
				case r := <-d.rows:
					batch = append(batch, r)
				default:
					flush()
					return
				}
			}
		case r := <-d.rows:
			batch = append(batch, r)
			if len(batch) >= 200 {
				flush()
			}
		case <-t.C:
			flush()
		case <-prune.C:
			if _, err := d.st.PurgeDNSDebug(ctx, time.Now().Add(-debugKeep)); err != nil {
				d.log.Warn("dns debug log: prune failed", "err", err)
			}
		}
	}
}

// export — записи журнала; anonymize — устройства «device-1, 2…» по порядку
// появления (домены остаются: без них ошибку не найти).
func (d *dnsDebug) export(ctx context.Context, anonymize bool) ([]store.DNSDebugRow, error) {
	rows, err := d.st.DNSDebug(ctx)
	if err != nil || !anonymize {
		return rows, err
	}
	names := map[string]string{}
	for i, r := range rows {
		n, ok := names[r.Device]
		if !ok {
			n = fmt.Sprintf("device-%d", len(names)+1)
			names[r.Device] = n
		}
		rows[i].Device = n
	}
	return rows, nil
}

// handle — команды сокета root.
func (d *dnsDebug) handle(ctx context.Context, req control.Request) (any, error) {
	switch req.Cmd {
	case "dns-log-start":
		return d.start(req.For)
	case "dns-log-stop":
		d.stop("stopped by command")
		return d.status(), nil
	case "dns-log-status":
		return d.status(), nil
	case "dns-log-export":
		return d.export(ctx, req.Anonymize)
	case "dns-log-purge":
		return d.st.PurgeDNSDebug(ctx, time.Time{})
	}
	return nil, fmt.Errorf("unknown command %q", req.Cmd)
}
