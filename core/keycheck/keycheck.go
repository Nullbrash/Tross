// Package keycheck содержит ограниченный исполнитель проверки импортированных
// прокси-выходов. Транспорт задаётся снаружи: сам пакет сеть не открывает.
package keycheck

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	MaxWorkers = 10
	MaxTargets = 7
)

type Kind string

const (
	Subscription Kind = "subscription"
	Outbound     Kind = "outbound"
)

// Record хранит исходную строку только в памяти. Raw нельзя сериализовать
// или писать в журнал: он может содержать учётные данные прокси.
type Record struct {
	ID   string `json:"id"`
	Kind Kind   `json:"kind"`
	Raw  string `json:"-"`
}

type InvalidLine struct {
	Line   int
	Reason string
}

// Parse разбирает строки локально. HTTPS остаётся подпиской: скачивание
// намеренно отсутствует и возможно только в отдельной фазе.
func Parse(lines []string) ([]Record, []InvalidLine) {
	seen := make(map[[32]byte]struct{})
	var records []Record
	var invalid []InvalidLine
	for number, line := range lines {
		raw := strings.TrimSpace(line)
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme == "" {
			invalid = append(invalid, InvalidLine{Line: number + 1, Reason: "unsupported_format"})
			continue
		}
		kind, ok := classify(parsed.Scheme)
		if !ok {
			invalid = append(invalid, InvalidLine{Line: number + 1, Reason: "unsupported_scheme"})
			continue
		}
		digest := sha256.Sum256([]byte(raw))
		if _, exists := seen[digest]; exists {
			continue
		}
		seen[digest] = struct{}{}
		records = append(records, Record{ID: randomID(), Kind: kind, Raw: raw})
	}
	return records, invalid
}

func classify(scheme string) (Kind, bool) {
	switch strings.ToLower(scheme) {
	case "http", "https":
		return Subscription, true
	case "vless", "vmess", "ss", "trojan", "hysteria", "hysteria2":
		return Outbound, true
	default:
		return "", false
	}
}

func randomID() string {
	var bytes [8]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		panic("keycheck: random record id: " + err.Error())
	}
	const hex = "0123456789abcdef"
	result := make([]byte, len(bytes)*2)
	for i, value := range bytes {
		result[i*2] = hex[value>>4]
		result[i*2+1] = hex[value&0x0f]
	}
	return string(result)
}

type Route string

const (
	RouteProxy   Route = "proxy"
	RouteDirect  Route = "direct"
	RouteBlocked Route = "blocked"
)

type Target struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type Selector interface {
	Route(record Record, target Target) Route
}

type ProbeStatus string

const (
	Reachable    ProbeStatus = "reachable"
	Unreachable  ProbeStatus = "unreachable"
	Inconclusive ProbeStatus = "inconclusive"
)

type ProbeResult struct {
	Status  ProbeStatus
	Latency time.Duration
	Reason  string
}

// Prober получает Raw только в момент проверки. Реализация должна избегать
// журналов и передавать выход лишь в выделенный маршрут стенда.
type Prober interface {
	Probe(ctx context.Context, record Record, target Target) ProbeResult
}

type Attempt struct {
	Target  string        `json:"target"`
	Route   Route         `json:"route"`
	Status  ProbeStatus   `json:"status,omitempty"`
	Latency time.Duration `json:"latency_ns,omitempty"`
	Reason  string        `json:"reason,omitempty"`
}

type Result struct {
	RecordID string    `json:"record_id"`
	Status   string    `json:"status"`
	Attempts []Attempt `json:"attempts"`
}

type Runner struct {
	Workers  int
	Timeout  time.Duration
	Targets  []Target
	Selector Selector
	Prober   Prober
}

// RunCheckpointed сохраняет начало и итог каждой записи отдельно. После
// аварии повторяется только то, что ещё не было начато.
func (r Runner) RunCheckpointed(ctx context.Context, checkpoint *Checkpoint, stateDir string, records []Record) ([]Result, error) {
	if checkpoint == nil || stateDir == "" {
		return nil, errors.New("keycheck: checkpoint and state directory are required")
	}
	if r.Selector == nil || r.Prober == nil || r.Timeout <= 0 {
		return nil, errors.New("keycheck: selector, prober and positive timeout are required")
	}
	pending := checkpoint.Pending(records)
	var saveMu sync.Mutex
	before := func(record Record) error {
		saveMu.Lock()
		defer saveMu.Unlock()
		checkpoint.MarkStarted(record)
		return checkpoint.Save(stateDir)
	}
	after := func(result Result) error {
		saveMu.Lock()
		defer saveMu.Unlock()
		checkpoint.MarkCompleted(result)
		return checkpoint.Save(stateDir)
	}
	return r.runWorkers(ctx, pending, before, after)
}

func (r Runner) Run(ctx context.Context, records []Record) ([]Result, error) {
	if r.Selector == nil || r.Prober == nil {
		return nil, errors.New("keycheck: selector and prober are required")
	}
	if r.Timeout <= 0 {
		return nil, errors.New("keycheck: positive timeout is required")
	}
	workers := r.Workers
	if workers <= 0 || workers > MaxWorkers {
		workers = MaxWorkers
	}
	return r.runWorkers(ctx, records, nil, nil)
}

func (r Runner) runWorkers(ctx context.Context, records []Record, before func(Record) error, after func(Result) error) ([]Result, error) {
	workers := r.Workers
	if workers <= 0 || workers > MaxWorkers {
		workers = MaxWorkers
	}
	targets := r.Targets
	if len(targets) > MaxTargets {
		targets = targets[:MaxTargets]
	}
	var mu sync.Mutex
	next := 0
	var firstErr error
	output := make([]Result, 0, len(records))
	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		for {
			mu.Lock()
			if firstErr != nil || ctx.Err() != nil || next == len(records) {
				mu.Unlock()
				return
			}
			record := records[next]
			next++
			mu.Unlock()
			if before != nil {
				if err := before(record); err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
					return
				}
			}
			result := r.runRecord(ctx, record, targets)
			if after != nil {
				if err := after(result); err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
					return
				}
			}
			mu.Lock()
			output = append(output, result)
			mu.Unlock()
		}
	}
	for range workers {
		wg.Add(1)
		go worker()
	}
	wg.Wait()
	return output, firstErr
}

func (r Runner) runRecord(parent context.Context, record Record, targets []Target) Result {
	result := Result{RecordID: record.ID, Status: "no_proxy_route"}
	proxyAttempts := 0
	reachable := 0
	unreachable := 0
	inconclusive := 0
	for _, target := range targets {
		route := r.Selector.Route(record, target)
		attempt := Attempt{Target: target.Name, Route: route}
		if route != RouteProxy {
			result.Attempts = append(result.Attempts, attempt)
			continue
		}
		proxyAttempts++
		ctx, cancel := context.WithTimeout(parent, r.Timeout)
		probe := r.Prober.Probe(ctx, record, target)
		cancel()
		attempt.Status, attempt.Latency, attempt.Reason = probe.Status, probe.Latency, probe.Reason
		result.Attempts = append(result.Attempts, attempt)
		switch probe.Status {
		case Reachable:
			reachable++
		case Unreachable:
			unreachable++
		default:
			inconclusive++
		}
	}
	if proxyAttempts == 0 {
		return result
	}
	// Для массового профиля пригодность означает успех на всём наборе,
	// частичный ответ остаётся отдельным состоянием, а не скрывается в успехе.
	switch {
	case reachable == proxyAttempts:
		result.Status = "working"
	case reachable > 0:
		result.Status = "unstable"
	case unreachable == proxyAttempts:
		result.Status = "not_working"
	case inconclusive > 0:
		result.Status = "unresolved"
	default:
		result.Status = "unresolved"
	}
	return result
}
