// Package resolver — DNS-резолвер сети (этап 4). Наружу — DoH/DoT через
// каналы. Для домена из правил и списков IP попадает в множество nftables ДО
// ответа клиенту: иначе первое соединение клиента уйдёт мимо нужного класса.
// Логика выбора серверов, кэш и решения по доменам — core/dns, core/lists.
package resolver

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	coredns "tross/core/dns"
	"tross/core/lists"
	"tross/core/model"
	"tross/internal/dataplane"
)

type Stats struct {
	Queries     uint64        `json:"queries"`
	CacheHits   uint64        `json:"cache_hits"`
	Failures    uint64        `json:"failures"`
	AvgUpstream time.Duration `json:"avg_upstream"`
}

// SetSink — множества ядра (dataplane.AddToSets).
type SetSink interface {
	AddToSets(ctx context.Context, elems []dataplane.SetElement) error
}

// Route — каналы для домена: через какой спросить DNS (у закреплённого
// устройства — его канал) и чей набор «домен → канал» получит адреса (для
// домена он один на всех; "" — не закреплять). ok=false — пригодных каналов нет.
type Route func(domain string, client netip.Addr) (query model.LinkID, pin dataplane.SetName, ok bool)

// UpstreamSpec — внешний сервер из конфига.
// UpstreamSpec — сервер: TLSName — имя для проверки сертификата сервера по
// IP без IP в сертификате.
type UpstreamSpec struct{ Name, URL, TLSName string }

type Config struct {
	Upstreams []UpstreamSpec
	Policy    *coredns.Policy
	Health    *coredns.Health
	Cache     *coredns.Cache
	Rules     *lists.Rules
	ClassSet  coredns.ClassSet
	// SetTTLMin, SetTTLMax — пределы срока адресов в множествах.
	SetTTLMin, SetTTLMax time.Duration
	Canary               bool
	Route                Route
	Sink                 SetSink
	Dial                 Dialer
	// RootCAs — корни для DoH/DoT; nil — системные (свои — для стенда).
	RootCAs *x509.CertPool
	// Timeout — ответ одного сервера.
	Timeout time.Duration
	// Hosts — свои имена (только устройствам из Home); наружу не уходят.
	Hosts map[string]netip.Addr
	// Home — сети дома (и сам мини-ПК).
	Home []netip.Prefix
	Log  *slog.Logger
}

type tlsRoots struct{ pool *x509.CertPool }

// Resolver — обработка запросов; слушатели — в server.go.
type Resolver struct {
	cfg   Config
	ups   map[string]*upstream
	sets  atomic.Pointer[coredns.SetIndex]
	debug atomic.Pointer[func(QueryLog)]

	flight sync.Mutex
	calls  map[coredns.Key]*call

	hosts sync.Map // имя сервера → hostEntry

	queries, hits, failures, upCount, upNanos atomic.Uint64
}

type call struct {
	done chan struct{}
	resp []byte
	err  error
}

type hostEntry struct {
	addrs []netip.Addr
	until time.Time
}

func New(cfg Config) (*Resolver, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 2500 * time.Millisecond
	}
	r := &Resolver{cfg: cfg, ups: map[string]*upstream{}, calls: map[coredns.Key]*call{}}
	r.sets.Store(coredns.NewSetIndex(nil))
	for _, s := range cfg.Upstreams {
		u, err := newUpstream(s.Name, s.URL, s.TLSName, tlsRoots{cfg.RootCAs}, cfg.Dial, r.lookupHost, cfg.Timeout)
		if err != nil {
			return nil, err
		}
		r.ups[s.Name] = u
	}
	return r, nil
}

// SetIndex — множества правил и профилей меняются вместе с классификацией.
func (r *Resolver) SetIndex(ix *coredns.SetIndex) { r.sets.Store(ix) }

func (r *Resolver) Stats() Stats {
	s := Stats{Queries: r.queries.Load(), CacheHits: r.hits.Load(), Failures: r.failures.Load()}
	if n := r.upCount.Load(); n > 0 {
		s.AvgUpstream = time.Duration(r.upNanos.Load() / n)
	}
	return s
}

// Close — закрыть соединения с серверами.
func (r *Resolver) Close() {
	for _, u := range r.ups {
		u.close()
	}
}

const (
	canaryName = "use-application-dns.net"
	// staleTTL — срок устаревшего ответа у клиента: скоро спросит снова и
	// получит обновлённый (RFC 8767).
	staleTTL = 30
)

// localName — имена, которые не уходят наружу: однословные и домашние
// зоны (ответ на них знает только дом; наружу — утечка имён устройств).
func localName(n string) bool {
	if !strings.Contains(n, ".") {
		return true
	}
	for _, z := range []string{"lan", "local", "home.arpa", "internal", "localhost"} {
		if n == z || strings.HasSuffix(n, "."+z) {
			return true
		}
	}
	return false
}

// Handle — ответ на запрос клиента; nil — не отвечать (не DNS). maxUDP —
// предел ответа по UDP; 0 — TCP.
func (r *Resolver) Handle(ctx context.Context, raw []byte, client netip.Addr, maxUDP int) []byte {
	q, err := parseQuery(raw)
	if err != nil {
		if len(raw) >= 12 {
			return reply(q, dnsmessage.RCodeFormatError, false)
		}
		return nil
	}
	r.queries.Add(1)
	hits := r.hits.Load()
	resp := r.answer(ctx, q, client)
	if log := r.debug.Load(); log != nil && len(resp) >= 4 {
		var link model.LinkID
		if r.cfg.Route != nil {
			link, _, _ = r.cfg.Route(q.Name, client)
		}
		(*log)(QueryLog{At: time.Now(), Client: client, Name: q.Name, Type: uint16(q.Type),
			RCode: uint16(resp[3] & 0x0f), Cached: r.hits.Load() != hits, Link: link})
	}
	if maxUDP > 0 && len(resp) > max(int(q.UDPSize), 512) {
		return reply(q, dnsmessage.RCodeSuccess, true)
	}
	return resp
}

// QueryLog — запрос для отладочного журнала. Cached — приблизительно: по
// счётчику попаданий (одновременные запросы могут спутать).
type QueryLog struct {
	At     time.Time
	Client netip.Addr
	Name   string
	Type   uint16
	RCode  uint16
	Cached bool
	Link   model.LinkID
}

// SetQueryLog — отладочный журнал: fn получает каждый запрос; nil —
// выключить (имена никуда не пишутся).
func (r *Resolver) SetQueryLog(fn func(QueryLog)) {
	if fn == nil {
		r.debug.Store(nil)
		return
	}
	r.debug.Store(&fn)
}

func (r *Resolver) answer(ctx context.Context, q query, client netip.Addr) []byte {
	switch {
	case q.Class != dnsmessage.ClassINET:
		return reply(q, dnsmessage.RCodeNotImplemented, false)
	case r.hostFor(q.Name, client).IsValid():
		return hostReply(q, r.hostFor(q.Name, client))
	case r.cfg.Canary && q.Name == canaryName:
		// Firefox отключает свой DoH, который обошёл бы резолвер (D-18).
		return reply(q, dnsmessage.RCodeNameError, false)
	case localName(q.Name):
		return reply(q, dnsmessage.RCodeNameError, false)
	case q.Type == dnsmessage.TypeAAAA:
		// IPv6 в v1 нет: адрес AAAA увёл бы соединение мимо классов и
		// каналов (а у клиента без IPv6 — к ожиданию перед IPv4).
		return reply(q, dnsmessage.RCodeSuccess, false)
	}
	key := coredns.Key{Name: q.Name, Type: uint16(q.Type), DO: q.DO}
	now := time.Now()
	hit := r.cfg.Cache.Get(key, now)
	switch hit.State {
	case coredns.Fresh, coredns.Stale:
		r.hits.Add(1)
		var fixed uint32
		if hit.State == coredns.Stale {
			fixed = staleTTL
		}
		// Адрес в множестве живёт max(TTL, нижний предел): к концу срока
		// устаревшего ответа его уже могло не быть — продлевается.
		if hit.State == coredns.Stale || now.Sub(hit.Stored) > r.cfg.SetTTLMin/2 {
			r.fillSets(ctx, q.Name, client, hit.Addrs, hit.TTL)
		}
		if hit.Refresh {
			go r.refresh(key, q, client)
		}
		resp, err := forClient(hit.Msg, q.ID, now.Sub(hit.Stored), fixed)
		if err == nil {
			return resp
		}
	}
	resp, err := r.shared(ctx, key, q, client)
	if err != nil {
		r.failures.Add(1)
		r.cfg.Log.Debug("dns failed", "name", q.Name, "err", err)
		return reply(q, dnsmessage.RCodeServerFailure, false)
	}
	out, err := forClient(resp, q.ID, 0, 0)
	if err != nil {
		return reply(q, dnsmessage.RCodeServerFailure, false)
	}
	return out
}

// shared — один поход наружу на одинаковые одновременные запросы.
func (r *Resolver) shared(ctx context.Context, key coredns.Key, q query, client netip.Addr) ([]byte, error) {
	r.flight.Lock()
	if c := r.calls[key]; c != nil {
		r.flight.Unlock()
		select {
		case <-c.done:
			return c.resp, c.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	c := &call{done: make(chan struct{})}
	r.calls[key] = c
	r.flight.Unlock()
	c.resp, c.err = r.resolve(ctx, key, q, client)
	r.flight.Lock()
	delete(r.calls, key)
	r.flight.Unlock()
	close(c.done)
	return c.resp, c.err
}

func (r *Resolver) refresh(key coredns.Key, q query, client netip.Addr) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*r.cfg.Timeout)
	defer cancel()
	if _, err := r.shared(ctx, key, q, client); err != nil {
		r.cfg.Cache.Abort(key)
	}
}

// resolve — к внешним серверам, адреса — в множества, ответ — в кэш.
func (r *Resolver) resolve(ctx context.Context, key coredns.Key, q query, client netip.Addr) ([]byte, error) {
	link, _, ok := r.cfg.Route(q.Name, client)
	if !ok {
		return nil, errors.New("no usable link")
	}
	plan := r.cfg.Policy.Plan(q.Name, link, time.Now())
	msg, err := buildQuery(randomID(), q.Name, q.Type, q.DO)
	if err != nil {
		return nil, err
	}
	resp, ans, err := r.exchange(ctx, plan, link, msg, q)
	if err != nil {
		return nil, err
	}
	r.fillSets(ctx, q.Name, client, ans.Addrs, ans.TTL)
	// SERVFAIL и обрезанное не кэшируются; ответ без срока — тоже.
	if ans.RCode != dnsmessage.RCodeServerFailure && !ans.Truncated && ans.TTL > 0 {
		r.cfg.Cache.Put(key, coredns.Entry{Msg: resp, Addrs: ans.Addrs, TTL: ans.TTL, Stored: time.Now()})
	}
	return resp, nil
}

// fillSets — адреса в множества ядра; клиент получает ответ только после
// ядра (D-16). Сбой ядра не оставляет клиента без ответа: соединение пойдёт
// по правилам без домена.
func (r *Resolver) fillSets(ctx context.Context, name string, client netip.Addr, addrs []netip.Addr, ttl time.Duration) {
	if len(addrs) == 0 {
		return
	}
	t := coredns.Decide(name, ttl, r.sets.Load(), r.cfg.Rules.Match(name), r.cfg.ClassSet, r.cfg.SetTTLMin, r.cfg.SetTTLMax)
	sets := slices.Clone(t.Sets)
	if _, pin, ok := r.cfg.Route(name, client); ok && pin != "" {
		sets = append(sets, string(pin))
	}
	if len(sets) == 0 {
		return
	}
	elems := make([]dataplane.SetElement, 0, len(sets)*len(addrs))
	for _, s := range sets {
		for _, a := range addrs {
			elems = append(elems, dataplane.SetElement{Set: dataplane.SetName(s), Addr: a, Timeout: t.Timeout})
		}
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if err := r.cfg.Sink.AddToSets(ctx, elems); err != nil {
		r.cfg.Log.Warn("dns: kernel sets not filled", "name", name, "err", err)
	}
}

type result struct {
	up   string
	resp []byte
	ans  answer
	err  error
}

// exchange — по плану: гонка или закреплённая доля со страховкой.
func (r *Resolver) exchange(ctx context.Context, plan coredns.Plan, link model.LinkID, msg []byte, q query) ([]byte, answer, error) {
	ctx, cancel := context.WithTimeout(ctx, r.cfg.Timeout+time.Second)
	defer cancel()
	results := make(chan result, len(plan.Upstreams))
	start := func(name string) {
		go func() { results <- r.ask(ctx, name, link, msg, q) }()
	}
	if plan.Race {
		race := coredns.NewRace(len(plan.Upstreams))
		got := map[string]result{}
		for _, n := range plan.Upstreams {
			start(n)
		}
		var grace <-chan time.Time
		for {
			select {
			case res := <-results:
				got[res.up] = res
				if race.Offer(coredns.Answer{Upstream: res.up, Empty: res.err == nil && res.ans.Empty(), Err: res.err}) {
					return pick(race, got)
				}
				if grace == nil && res.err == nil {
					// Пустой ответ пришёл первым: немного подождать непустого.
					grace = time.After(100 * time.Millisecond)
				}
			case <-grace:
				race.Settle()
				return pick(race, got)
			case <-ctx.Done():
				race.Settle()
				return pick(race, got)
			}
		}
	}
	// Закреплённая доля: следующий сервер — при сбое или без ответа через
	// HedgeAfter (его увидит ещё один, а не все).
	next, pending := 0, 0
	launch := func() bool {
		if next >= len(plan.Upstreams) {
			return false
		}
		start(plan.Upstreams[next])
		next++
		pending++
		return true
	}
	launch()
	var errs []error
	for pending > 0 {
		hedge := time.After(r.cfg.Policy.Params().HedgeAfter)
		select {
		case res := <-results:
			pending--
			if res.err == nil {
				return res.resp, res.ans, nil
			}
			errs = append(errs, res.err)
			if pending == 0 && !launch() {
				return nil, answer{}, errors.Join(errs...)
			}
		case <-hedge:
			launch()
		case <-ctx.Done():
			return nil, answer{}, errors.Join(append(errs, ctx.Err())...)
		}
	}
	return nil, answer{}, errors.Join(errs...)
}

func pick(race *coredns.Race, got map[string]result) ([]byte, answer, error) {
	w, ok := race.Winner()
	if !ok {
		return nil, answer{}, errors.New("no answer")
	}
	if w.Err != nil {
		return nil, answer{}, w.Err
	}
	res := got[w.Upstream]
	return res.resp, res.ans, nil
}

// ask — один сервер; SERVFAIL и REFUSED — сбой сервера (и для здоровья).
func (r *Resolver) ask(ctx context.Context, name string, link model.LinkID, msg []byte, q query) result {
	u := r.ups[name]
	if u == nil {
		return result{up: name, err: fmt.Errorf("unknown upstream %q", name)}
	}
	h := r.cfg.Health
	h.Begin(name, link)
	t0 := time.Now()
	resp, err := u.exchange(ctx, link, msg)
	var ans answer
	if err == nil {
		ans, err = inspect(resp, q.Name, q.Type)
	}
	if err == nil && (ans.RCode == dnsmessage.RCodeServerFailure || ans.RCode == dnsmessage.RCodeRefused) {
		err = fmt.Errorf("%s: %v", name, ans.RCode)
	}
	rtt := time.Since(t0)
	h.Done(name, link, time.Now(), rtt, err == nil)
	if err == nil {
		r.upCount.Add(1)
		r.upNanos.Add(uint64(rtt))
	}
	return result{up: name, resp: resp, ans: ans, err: err}
}

// lookupHost — адреса имени внешнего сервера (заданного именем) через
// серверы быстрого набора, заданные по IP.
func (r *Resolver) lookupHost(ctx context.Context, host string, link model.LinkID) ([]netip.Addr, error) {
	if e, ok := r.hosts.Load(host); ok && time.Now().Before(e.(hostEntry).until) {
		return e.(hostEntry).addrs, nil
	}
	msg, err := buildQuery(randomID(), host, dnsmessage.TypeA, false)
	if err != nil {
		return nil, err
	}
	var errs []error
	for name, u := range r.ups {
		if _, err := netip.ParseAddr(u.host); err != nil {
			continue
		}
		res := r.ask(ctx, name, link, msg, query{Name: host, Type: dnsmessage.TypeA})
		if res.err == nil && len(res.ans.Addrs) > 0 {
			r.hosts.Store(host, hostEntry{res.ans.Addrs, time.Now().Add(max(res.ans.TTL, 10*time.Minute))})
			return res.ans.Addrs, nil
		}
		errs = append(errs, res.err)
	}
	return nil, errors.Join(append(errs, fmt.Errorf("%s: no address", host))...)
}

func randomID() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}

// hostTTL — срок своего имени: адрес в доме меняется редко, но правка
// конфига должна дойти до устройств быстро.
const hostTTL = 60

// hostFor — свой адрес имени для этого клиента; невалиден — нет такого или
// клиент не из дома (снаружи своё имя отвечает внешний DNS).
func (r *Resolver) hostFor(name string, client netip.Addr) netip.Addr {
	a, ok := r.cfg.Hosts[name]
	if !ok || !(client.IsLoopback() || slices.ContainsFunc(r.cfg.Home, func(p netip.Prefix) bool { return p.Contains(client) })) {
		return netip.Addr{}
	}
	return a
}

// hostReply — A — свой адрес; другие типы — пусто (имя есть, записей нет).
func hostReply(q query, a netip.Addr) []byte {
	if q.Type != dnsmessage.TypeA {
		return reply(q, dnsmessage.RCodeSuccess, false)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: q.ID, Response: true, Authoritative: true, RecursionDesired: q.RD, RecursionAvailable: true})
	_ = b.StartQuestions()
	_ = b.Question(q.question)
	_ = b.StartAnswers()
	_ = b.AResource(dnsmessage.ResourceHeader{Name: q.question.Name, Class: dnsmessage.ClassINET, TTL: hostTTL}, dnsmessage.AResource{A: a.As4()})
	out, err := b.Finish()
	if err != nil {
		return reply(q, dnsmessage.RCodeServerFailure, false)
	}
	return out
}
