package dpi

import (
	"sync"
	"time"

	"tross/core/model"
)

// Pacer — не больше N подключений пробника к одному имени за окно: у ТСПУ
// порог «больше 3 TLS к имени за минуту — заморозка» задел бы и настоящее
// открытие сайта.
type Pacer struct {
	N      int
	Window time.Duration

	mu   sync.Mutex
	seen map[string][]time.Time
}

// NewPacer — по умолчанию 2 за минуту.
func NewPacer() *Pacer { return &Pacer{N: 2, Window: time.Minute} }

// Allow — можно ли подключиться к name сейчас; да — подключение учтено.
func (p *Pacer) Allow(name string, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.seen == nil {
		p.seen = map[string][]time.Time{}
	}
	ts := p.seen[name][:0]
	for _, t := range p.seen[name] {
		if now.Sub(t) < p.Window {
			ts = append(ts, t)
		}
	}
	if len(ts) >= p.N {
		p.seen[name] = ts
		return false
	}
	p.seen[name] = append(ts, now)
	return true
}

// Wait — через сколько можно подключиться к name (0 — сейчас), не учитывая.
func (p *Pacer) Wait(name string, now time.Time) time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	var live []time.Time
	for _, t := range p.seen[name] {
		if now.Sub(t) < p.Window {
			live = append(live, t)
		}
	}
	if len(live) < p.N {
		return 0
	}
	return live[len(live)-p.N].Add(p.Window).Sub(now)
}

// CheckParams — когда проверять домен на канале.
type CheckParams struct {
	// Recheck — перепроверка «без обхода» и стратегии домена.
	Recheck time.Duration
	// Active — перепроверяются только домены, которыми пользовались за
	// этот срок: неиспользуемые из списков не трогаются.
	Active time.Duration
	// Retry — повтор после «проверить не удалось» (канал был плох).
	Retry time.Duration
}

func DefaultCheckParams() CheckParams {
	return CheckParams{Recheck: 24 * time.Hour, Active: 3 * 24 * time.Hour, Retry: 15 * time.Minute}
}

// CheckDue — пора ли проверять домен на канале: решения нет и домен только
// что спросили; решение устарело, а домен в ходу; прошлая проверка не
// удалась.
func CheckDue(v *Verdict, lastUsed, now time.Time, p CheckParams) bool {
	if now.Sub(lastUsed) > p.Active {
		return false
	}
	if v == nil {
		return true
	}
	if v.Method == MethodUnknown {
		return now.Sub(v.CheckedAt) >= p.Retry
	}
	return now.Sub(v.CheckedAt) >= p.Recheck
}

// RunReason — повод подобрать стратегии канала заново.
type RunReason string

const (
	// RunNoStrategy — сохранённых стратегий канала нет (первый запуск).
	RunNoStrategy RunReason = "no_strategy"
	// RunAddressChanged — сменился адрес или провайдер канала.
	RunAddressChanged RunReason = "address_changed"
	// RunDaily — плановая перепроверка.
	RunDaily RunReason = "daily"
	// RunRotationExhausted — ротация на живом трафике перебрала все
	// стратегии, а неудачи продолжаются.
	RunRotationExhausted RunReason = "rotation_exhausted"
	// RunManual — по команде пользователя.
	RunManual RunReason = "manual"
)

// RunAllowed — подбор на канале по поводу: на LTE (платный по умолчанию
// канал) — только по команде.
func RunAllowed(kind model.LinkKind, why RunReason) bool {
	return why == RunManual || kind != model.LinkKindLTE
}
