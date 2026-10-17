package dns

import (
	"sync"
	"time"

	"tross/core/model"
)

// Health — здоровье внешних серверов по каждому каналу: один и тот же
// сервер через одного провайдера работает, через другого — режется.
// Только по настоящим запросам — отдельных проб нет. Потокобезопасен.
type Health struct {
	mu sync.Mutex
	m  map[healthKey]*healthState
	p  HealthParams
}

type HealthParams struct {
	// FailAfter — столько сбоев подряд, и сервер откладывается на Backoff
	// (каждый следующий раз вдвое дольше, до MaxBackoff).
	FailAfter           int
	Backoff, MaxBackoff time.Duration
	// Unknown — оценка задержки сервера без замеров: новый сервер не
	// должен ни побеждать проверенных, ни никогда не пробоваться.
	Unknown time.Duration
}

func DefaultHealthParams() HealthParams {
	return HealthParams{FailAfter: 3, Backoff: 30 * time.Second, MaxBackoff: 5 * time.Minute, Unknown: 100 * time.Millisecond}
}

type healthKey struct {
	up   string
	link model.LinkID
}

type healthState struct {
	rtt       time.Duration // скользящее среднее (1/4 нового замера)
	fails     int
	backoff   time.Duration
	downUntil time.Time
	pending   int
	ok, bad   uint64
	last      time.Time
}

func NewHealth(p HealthParams) *Health {
	return &Health{m: map[healthKey]*healthState{}, p: p}
}

func (h *Health) state(up string, link model.LinkID) *healthState {
	k := healthKey{up, link}
	s := h.m[k]
	if s == nil {
		s = &healthState{}
		h.m[k] = s
	}
	return s
}

// Begin — запрос ушёл; Done обязателен.
func (h *Health) Begin(up string, link model.LinkID) {
	h.mu.Lock()
	h.state(up, link).pending++
	h.mu.Unlock()
}

// Done — итог запроса: ok — пришёл ответ DNS (SERVFAIL и REFUSED — сбой).
func (h *Health) Done(up string, link model.LinkID, now time.Time, rtt time.Duration, ok bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.state(up, link)
	if s.pending > 0 {
		s.pending--
	}
	s.last = now
	if ok {
		s.ok++
		s.fails, s.backoff = 0, 0
		if s.rtt == 0 {
			s.rtt = rtt
		} else {
			s.rtt += (rtt - s.rtt) / 4
		}
		return
	}
	s.bad++
	s.fails++
	if s.fails >= h.p.FailAfter {
		s.backoff = min(max(s.backoff*2, h.p.Backoff), h.p.MaxBackoff)
		s.downUntil = now.Add(s.backoff)
		s.fails = 0
	}
}

// Usable — сервер не отложен и не перегружен ожидающими запросами.
func (h *Health) Usable(up string, link model.LinkID, now time.Time, maxPending int) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.m[healthKey{up, link}]
	return s == nil || now.After(s.downUntil) && (maxPending <= 0 || s.pending < maxPending)
}

// Score — чем меньше, тем лучше: задержка с поправкой на сбои подряд.
func (h *Health) Score(up string, link model.LinkID) time.Duration {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.m[healthKey{up, link}]
	if s == nil || s.ok == 0 {
		return h.p.Unknown
	}
	return s.rtt * time.Duration(1+s.fails)
}

// UpstreamHealth — снимок для API.
type UpstreamHealth struct {
	Upstream  string        `json:"upstream"`
	Link      model.LinkID  `json:"link"`
	RTT       time.Duration `json:"rtt"`
	OK        uint64        `json:"ok"`
	Failed    uint64        `json:"failed"`
	Pending   int           `json:"pending"`
	DownUntil time.Time     `json:"down_until,omitzero"`
	Last      time.Time     `json:"last,omitzero"`
}

func (h *Health) Snapshot() []UpstreamHealth {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]UpstreamHealth, 0, len(h.m))
	for k, s := range h.m {
		out = append(out, UpstreamHealth{Upstream: k.up, Link: k.link, RTT: s.rtt, OK: s.ok, Failed: s.bad, Pending: s.pending, DownUntil: s.downUntil, Last: s.last})
	}
	return out
}
