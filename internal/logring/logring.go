// Package logring — кольцевой буфер свежих записей журнала для интерфейса:
// обёртка над slog.Handler, которая копирует каждую запись в память.
package logring

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"
)

type Entry struct {
	Time  time.Time      `json:"time"`
	Level string         `json:"level"`
	Msg   string         `json:"msg"`
	Attrs map[string]any `json:"attrs,omitempty"`
	level slog.Level
}

// Ring хранит не больше size последних записей; старые вытесняются.
type Ring struct {
	mu   sync.Mutex
	buf  []Entry
	next int
	full bool
}

func New(size int) *Ring { return &Ring{buf: make([]Entry, max(size, 1))} }

func (r *Ring) add(e Entry) {
	r.mu.Lock()
	r.buf[r.next] = e
	r.next = (r.next + 1) % len(r.buf)
	if r.next == 0 {
		r.full = true
	}
	r.mu.Unlock()
}

// Entries — до limit последних записей не ниже уровня min, от старых к новым;
// limit <= 0 — все.
func (r *Ring) Entries(min slog.Level, limit int) []Entry {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := r.next
	if r.full {
		n = len(r.buf)
	}
	var out []Entry
	// Идём от новых к старым, чтобы limit отсекал старое.
	for i := 1; i <= n && (limit <= 0 || len(out) < limit); i++ {
		e := r.buf[(r.next-i+len(r.buf))%len(r.buf)]
		if e.level >= min {
			out = append(out, e)
		}
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// Wrap возвращает обработчик, который пишет в next и в кольцо. Уровень
// отсечения — тот же, что у next: в кольце не больше, чем в журнале.
func (r *Ring) Wrap(next slog.Handler) slog.Handler { return &handler{next: next, ring: r} }

type handler struct {
	next   slog.Handler
	ring   *Ring
	attrs  []slog.Attr // с уже применённым префиксом групп
	prefix string
}

func (h *handler) Enabled(ctx context.Context, l slog.Level) bool { return h.next.Enabled(ctx, l) }

func (h *handler) Handle(ctx context.Context, rec slog.Record) error {
	e := Entry{Time: rec.Time, Level: rec.Level.String(), Msg: rec.Message, level: rec.Level}
	if len(h.attrs) > 0 || rec.NumAttrs() > 0 {
		e.Attrs = make(map[string]any, len(h.attrs)+rec.NumAttrs())
		for _, a := range h.attrs {
			put(e.Attrs, "", a)
		}
		rec.Attrs(func(a slog.Attr) bool {
			put(e.Attrs, h.prefix, a)
			return true
		})
	}
	h.ring.add(e)
	return h.next.Handle(ctx, rec)
}

func (h *handler) WithAttrs(as []slog.Attr) slog.Handler {
	c := *h
	c.next = h.next.WithAttrs(as)
	c.attrs = append([]slog.Attr(nil), h.attrs...)
	for _, a := range as {
		a.Key = h.prefix + a.Key
		c.attrs = append(c.attrs, a)
	}
	return &c
}

func (h *handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	c := *h
	c.next = h.next.WithGroup(name)
	c.prefix = h.prefix + name + "."
	return &c
}

// put раскрывает группы в плоские ключи «группа.ключ». Сложные значения
// приводятся к строке: интерфейсу нужен читаемый текст, а не структура
// (ошибка в JSON иначе превратилась бы в {}).
func put(m map[string]any, prefix string, a slog.Attr) {
	v := a.Value.Resolve()
	if a.Equal(slog.Attr{}) {
		return
	}
	key := prefix + a.Key
	switch v.Kind() {
	case slog.KindGroup:
		p := key + "."
		if a.Key == "" {
			p = prefix
		}
		for _, g := range v.Group() {
			put(m, p, g)
		}
	case slog.KindString:
		m[key] = v.String()
	case slog.KindInt64:
		m[key] = v.Int64()
	case slog.KindUint64:
		m[key] = v.Uint64()
	case slog.KindFloat64:
		m[key] = v.Float64()
	case slog.KindBool:
		m[key] = v.Bool()
	default:
		m[key] = strings.TrimSpace(v.String())
	}
}
