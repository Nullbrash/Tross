package api

import (
	"errors"
	"log/slog"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"tross/core/model"
	"tross/internal/store"
)

const (
	defaultEvents = 100
	maxEvents     = 1000
	defaultLogs   = 200
)

// Окно по умолчанию и предел запроса статистики: поминутные строки за 90 дней
// дали бы десятки мегабайт JSON, поэтому их окно ограничено неделей.
var statWindows = map[store.Resolution]struct{ def, max time.Duration }{
	store.ResMinute: {6 * time.Hour, 7 * 24 * time.Hour},
	store.ResHour:   {7 * 24 * time.Hour, 180 * 24 * time.Hour},
	store.ResDay:    {90 * 24 * time.Hour, 366 * 24 * time.Hour},
}

func badRequest(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
}

func intParam(r *http.Request, name string, def, maxV int) (int, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return 0, errors.New(name + ": positive integer expected")
	}
	return min(n, maxV), nil
}

func timeParam(r *http.Request, name string, def time.Time) (time.Time, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def, nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, errors.New(name + ": RFC 3339 time expected")
	}
	return t, nil
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	limit, err := intParam(r, "limit", defaultEvents, maxEvents)
	if err != nil {
		badRequest(w, err)
		return
	}
	since, err := timeParam(r, "since", time.Time{})
	if err != nil {
		badRequest(w, err)
		return
	}
	evs, err := s.opts.Store.Events(r.Context(), since, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": evs})
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	limit, err := intParam(r, "limit", defaultLogs, 1<<20)
	if err != nil {
		badRequest(w, err)
		return
	}
	var lvl slog.Level
	if v := r.URL.Query().Get("level"); v != "" {
		if err := lvl.UnmarshalText([]byte(strings.ToUpper(v))); err != nil {
			badRequest(w, errors.New("level: debug | info | warn | error"))
			return
		}
	} else {
		lvl = slog.LevelDebug
	}
	writeJSON(w, http.StatusOK, map[string]any{"logs": nonNil(s.opts.Logs.Entries(lvl, limit))})
}

type linkCounters struct {
	ID      model.LinkID `json:"id"`
	RxBytes uint64       `json:"rx_bytes"`
	TxBytes uint64       `json:"tx_bytes"`
}

func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	var links []linkCounters
	for _, st := range s.opts.Monitor.Snapshot() {
		links = append(links, linkCounters{ID: st.Link.ID, RxBytes: st.Health.RxBytes, TxBytes: st.Health.TxBytes})
	}
	var sys *store.SystemSample
	if s.opts.System != nil {
		sys = s.opts.System()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"uptime_seconds": int64(time.Since(s.started).Seconds()),
		"goroutines":     runtime.NumGoroutine(),
		"go_heap_mb":     float64(ms.HeapAlloc) / (1 << 20),
		"go_sys_mb":      float64(ms.Sys) / (1 << 20),
		"db_size_bytes":  s.opts.Store.SizeBytes(),
		"system":         sys, // последняя поминутная выборка; null вне Linux
		"links":          links,
	})
}

// statRange разбирает res/from/to; to по умолчанию — сейчас.
func statRange(r *http.Request) (store.Resolution, time.Time, time.Time, error) {
	res := store.Resolution(r.URL.Query().Get("res"))
	if res == "" {
		res = store.ResHour
	}
	win, ok := statWindows[res]
	if !ok {
		return "", time.Time{}, time.Time{}, errors.New("res: minute | hour | day")
	}
	to, err := timeParam(r, "to", time.Now())
	if err != nil {
		return "", time.Time{}, time.Time{}, err
	}
	from, err := timeParam(r, "from", to.Add(-win.def))
	if err != nil {
		return "", time.Time{}, time.Time{}, err
	}
	if !from.Before(to) {
		return "", time.Time{}, time.Time{}, errors.New("from must be before to")
	}
	if to.Sub(from) > win.max {
		return "", time.Time{}, time.Time{}, errors.New("range too large for res=" + string(res) + ", max " + win.max.String())
	}
	return res, from, to, nil
}

func (s *Server) handleLinkStats(w http.ResponseWriter, r *http.Request) {
	id := model.LinkID(r.PathValue("id"))
	if _, ok := s.opts.Monitor.Status(id); !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown link"})
		return
	}
	res, from, to, err := statRange(r)
	if err != nil {
		badRequest(w, err)
		return
	}
	rows, err := s.opts.Store.LinkStats(r.Context(), id, res, from, to)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"link": id, "res": res, "from": from, "to": to, "stats": nonNil(rows)})
}

func (s *Server) handleSystemStats(w http.ResponseWriter, r *http.Request) {
	res, from, to, err := statRange(r)
	if err != nil {
		badRequest(w, err)
		return
	}
	rows, err := s.opts.Store.SystemStats(r.Context(), res, from, to)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"res": res, "from": from, "to": to, "stats": nonNil(rows)})
}

// nonNil — пустой список отдаётся как [], а не null: интерфейсу проще.
func nonNil[T any](v []T) []T {
	if v == nil {
		return []T{}
	}
	return v
}
