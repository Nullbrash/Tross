// Package lists — загрузка онлайн-списков доменов: расписание, кеш на
// диске, разбор и замена слоя онлайн в core/lists. Недоступный или битый
// источник не ломает работу: действует прежний кеш.
package lists

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"time"

	corelists "tross/core/lists"
	"tross/core/model"
)

// Fetched — ответ источника. NotModified — с прошлой загрузки не менялся
// (условный запрос): тело не передаётся.
type Fetched struct {
	Body        io.ReadCloser
	ETag        string
	NotModified bool
}

// Fetcher — загрузка по URL (через канал); etag — от прошлой загрузки.
type Fetcher func(ctx context.Context, url, etag string) (Fetched, error)

type Options struct {
	Sources []corelists.Source
	// Interval — общий период обновления; у источника может быть свой.
	Interval time.Duration
	// Dir — кеш на диске; "" — без кеша (сухой режим без каталога данных).
	Dir   string
	Rules *corelists.Rules
	// Fetch — nil: только кеш (сухой режим не ходит в сеть).
	Fetch Fetcher
	// MaxBytes — предел размера источника.
	MaxBytes int64
	// Retry — повтор после сбоя (не чаще периода источника).
	Retry time.Duration
	Log   *slog.Logger
}

// meta — сведения о загрузке рядом с кешем.
type meta struct {
	ETag      string    `json:"etag,omitempty"`
	Checksum  string    `json:"checksum,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
	Domains   int       `json:"domains"`
}

type Manager struct {
	opts Options

	mu     sync.Mutex
	status map[string]*corelists.SourceStatus
	meta   map[string]meta
	failed map[string]time.Time
}

func New(opts Options) *Manager {
	if opts.MaxBytes == 0 {
		opts.MaxBytes = 128 << 20
	}
	if opts.Retry == 0 {
		opts.Retry = time.Hour
	}
	m := &Manager{opts: opts, status: map[string]*corelists.SourceStatus{}, meta: map[string]meta{}, failed: map[string]time.Time{}}
	for _, s := range opts.Sources {
		m.status[s.ID] = &corelists.SourceStatus{Source: s}
	}
	return m
}

func (m *Manager) enabled() []corelists.Source {
	return slices.DeleteFunc(slices.Clone(m.opts.Sources), func(s corelists.Source) bool { return s.Disabled })
}

func (m *Manager) interval(s corelists.Source) time.Duration {
	if s.Interval > 0 {
		return s.Interval
	}
	return m.opts.Interval
}

func (m *Manager) dataPath(id string) string { return filepath.Join(m.opts.Dir, id+".list") }
func (m *Manager) metaPath(id string) string { return filepath.Join(m.opts.Dir, id+".json") }

// LoadCache — правила из кеша до первой загрузки: перезапуск не оставляет
// дом без списков.
func (m *Manager) LoadCache() {
	if m.opts.Dir == "" {
		return
	}
	for _, s := range m.enabled() {
		var md meta
		if b, err := os.ReadFile(m.metaPath(s.ID)); err == nil {
			_ = json.Unmarshal(b, &md)
		}
		data, err := os.ReadFile(m.dataPath(s.ID))
		if err != nil {
			continue
		}
		if err := m.apply(s, data, md); err != nil {
			m.opts.Log.Warn("lists: cached source unreadable", "source", s.ID, "err", err)
		}
	}
}

// bigList — после такого списка память разбора отдаётся системе сразу.
const bigList = 100_000

// apply — разобрать и заменить правила источника.
func (m *Manager) apply(s corelists.Source, data []byte, md meta) error {
	var p corelists.Parsed
	var err error
	switch s.Format {
	case corelists.FormatGeosite:
		p, err = corelists.ParseGeosite(data, s.Categories)
	default:
		p, err = corelists.ParseText(bytes.NewReader(data))
	}
	if err != nil {
		return err
	}
	if len(p.Entries) == 0 {
		return errors.New("no domains")
	}
	if err := m.opts.Rules.SetOnline(s.ID, model.DomainRule{Purpose: s.Purpose, Class: s.Class}, p.Entries); err != nil {
		// Неверные правила отброшены, остальные действуют — для журнала.
		m.opts.Log.Debug("lists: some rules rejected", "source", s.ID, "err", err)
	}
	md.Domains = len(p.Entries)
	if len(p.Entries) >= bigList {
		// Разбор большого списка — сотни МБ временной памяти; Go сам отдаёт
		// её системе медленно, а списки обновляются раз в сутки.
		p = corelists.Parsed{}
		debug.FreeOSMemory()
	}
	m.mu.Lock()
	m.meta[s.ID] = md
	st := m.status[s.ID]
	st.Domains, st.UpdatedAt, st.Error = md.Domains, md.UpdatedAt, ""
	m.mu.Unlock()
	return nil
}

// Run — обновление по расписанию до отмены ctx.
func (m *Manager) Run(ctx context.Context) {
	if m.opts.Fetch == nil {
		return
	}
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		for _, s := range m.enabled() {
			if m.due(s, time.Now()) {
				if err := m.refresh(ctx, s); err != nil && ctx.Err() == nil && !errors.Is(err, ErrNoLink) {
					m.opts.Log.Warn("lists: refresh failed, cached list stays", "source", s.ID, "err", err)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (m *Manager) due(s corelists.Source, now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if f, ok := m.failed[s.ID]; ok && now.Sub(f) < min(m.opts.Retry, m.interval(s)) {
		return false
	}
	return now.Sub(m.meta[s.ID].UpdatedAt) >= m.interval(s)
}

// Refresh — загрузить источник сейчас; "" — все включённые.
func (m *Manager) Refresh(ctx context.Context, id string) error {
	if m.opts.Fetch == nil {
		return errors.New("lists: downloads are off (dry run)")
	}
	var errs []error
	found := false
	for _, s := range m.enabled() {
		if id == "" || s.ID == id {
			found = true
			if err := m.refresh(ctx, s); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", s.ID, err))
			}
		}
	}
	if !found {
		return fmt.Errorf("lists: no enabled source %q", id)
	}
	return errors.Join(errs...)
}

func (m *Manager) refresh(ctx context.Context, s corelists.Source) (err error) {
	defer func() {
		m.mu.Lock()
		if err != nil {
			// Без канала пауза после сбоя не ставится: иначе после запуска
			// (каналы ещё не подняты) список ждал бы час.
			if !errors.Is(err, ErrNoLink) {
				m.failed[s.ID] = time.Now()
			}
			m.status[s.ID].Error = err.Error()
		} else {
			delete(m.failed, s.ID)
		}
		m.mu.Unlock()
	}()
	m.mu.Lock()
	old := m.meta[s.ID]
	m.mu.Unlock()
	md := meta{ETag: old.ETag, Checksum: old.Checksum}
	// Контрольная сумма — десятки байт вместо файла: большой geosite
	// перекачивается, только если сменился.
	if s.Checksum != "" {
		sum, err := m.fetchSmall(ctx, s.Checksum)
		if err != nil {
			return fmt.Errorf("checksum: %w", err)
		}
		if sum != "" && sum == old.Checksum && !old.UpdatedAt.IsZero() {
			return m.touch(s, old)
		}
		md.Checksum = sum
	}
	f, err := m.opts.Fetch(ctx, s.URL, old.ETag)
	if err != nil {
		return err
	}
	if f.NotModified {
		return m.touch(s, md)
	}
	defer f.Body.Close()
	data, err := io.ReadAll(io.LimitReader(f.Body, m.opts.MaxBytes+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > m.opts.MaxBytes {
		return fmt.Errorf("larger than %d bytes", m.opts.MaxBytes)
	}
	md.ETag, md.UpdatedAt = f.ETag, time.Now()
	// Сначала разбор: битый файл не заменяет рабочий кеш.
	if err := m.apply(s, data, md); err != nil {
		return err
	}
	if err := m.save(s.ID, data, md); err != nil {
		m.opts.Log.Warn("lists: cache not written", "source", s.ID, "err", err)
	}
	m.mu.Lock()
	n := m.meta[s.ID].Domains
	m.mu.Unlock()
	m.opts.Log.Info("lists: source updated", "source", s.ID, "domains", n, "bytes", len(data))
	return nil
}

// touch — источник не менялся: продлить срок.
func (m *Manager) touch(s corelists.Source, md meta) error {
	m.mu.Lock()
	md.Domains = m.meta[s.ID].Domains
	m.mu.Unlock()
	md.UpdatedAt = time.Now()
	m.mu.Lock()
	m.meta[s.ID] = md
	m.status[s.ID].UpdatedAt, m.status[s.ID].Error = md.UpdatedAt, ""
	m.mu.Unlock()
	return m.saveMeta(s.ID, md)
}

func (m *Manager) fetchSmall(ctx context.Context, url string) (string, error) {
	f, err := m.opts.Fetch(ctx, url, "")
	if err != nil {
		return "", err
	}
	if f.Body == nil {
		return "", nil
	}
	defer f.Body.Close()
	b, err := io.ReadAll(io.LimitReader(f.Body, 4096))
	if err != nil {
		return "", err
	}
	// «хеш  имя-файла» — берётся хеш.
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return "", errors.New("empty checksum")
	}
	return fields[0], nil
}

// save — кеш атомарно: оборванная запись не портит прежний файл.
func (m *Manager) save(id string, data []byte, md meta) error {
	if m.opts.Dir == "" {
		return nil
	}
	if err := os.MkdirAll(m.opts.Dir, 0o750); err != nil {
		return err
	}
	tmp := m.dataPath(id) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return err
	}
	if err := os.Rename(tmp, m.dataPath(id)); err != nil {
		return err
	}
	return m.saveMeta(id, md)
}

func (m *Manager) saveMeta(id string, md meta) error {
	if m.opts.Dir == "" {
		return nil
	}
	b, _ := json.Marshal(md)
	tmp := m.metaPath(id) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, m.metaPath(id))
}

// Sources — состояние источников (и выключенных — для API).
func (m *Manager) Sources() []corelists.SourceStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]corelists.SourceStatus, 0, len(m.opts.Sources))
	for _, s := range m.opts.Sources {
		out = append(out, *m.status[s.ID])
	}
	return out
}

// ClassRule — первое правило класса для классификатора: более важное
// правило без класса (обход) не должно прятать класс из списков.
func ClassRule(rules *corelists.Rules) func(string) (model.DomainRule, bool) {
	return func(domain string) (model.DomainRule, bool) {
		for _, r := range rules.Match(domain) {
			if r.Purpose == model.PurposeClass || r.Purpose == "" && r.Class != "" {
				return r, true
			}
		}
		return model.DomainRule{}, false
	}
}
