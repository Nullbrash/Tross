package resolver

import (
	"context"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	coredns "tross/core/dns"
	"tross/core/lists"
	"tross/core/model"
	"tross/internal/dataplane"
)

// fakeDoH — подставной сервер: ответ по имени.
type fakeDoH struct {
	srv   *httptest.Server
	hits  atomic.Int64
	mu    sync.Mutex
	names map[string]fakeAnswer
}

type fakeAnswer struct {
	addr  string // "" — без адресов
	rcode dnsmessage.RCode
	delay time.Duration
	ttl   uint32
	extra int // лишние TXT-записи (для проверки обрезки по UDP)
}

func newFakeDoH(t *testing.T) *fakeDoH {
	f := &fakeDoH{names: map[string]fakeAnswer{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		var p dnsmessage.Parser
		h, err := p.Start(body)
		if err != nil {
			http.Error(w, "bad", 400)
			return
		}
		q, _ := p.Question()
		name := strings.TrimSuffix(q.Name.String(), ".")
		f.mu.Lock()
		a, ok := f.names[name]
		f.mu.Unlock()
		if !ok {
			a = fakeAnswer{rcode: dnsmessage.RCodeNameError}
		}
		time.Sleep(a.delay)
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionAvailable: true, RCode: a.rcode})
		_ = b.StartQuestions()
		_ = b.Question(q)
		_ = b.StartAnswers()
		ttl := a.ttl
		if ttl == 0 {
			ttl = 300
		}
		if a.addr != "" && q.Type == dnsmessage.TypeA {
			_ = b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: ttl}, dnsmessage.AResource{A: netip.MustParseAddr(a.addr).As4()})
		}
		for range a.extra {
			_ = b.TXTResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: ttl}, dnsmessage.TXTResource{TXT: []string{strings.Repeat("x", 200)}})
		}
		out, _ := b.Finish()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeDoH) set(name string, a fakeAnswer) {
	f.mu.Lock()
	f.names[name] = a
	f.mu.Unlock()
}

// recSink — элементы множеств и момент их появления.
type recSink struct {
	mu    sync.Mutex
	elems []dataplane.SetElement
}

func (s *recSink) AddToSets(_ context.Context, e []dataplane.SetElement) error {
	s.mu.Lock()
	s.elems = append(s.elems, e...)
	s.mu.Unlock()
	return nil
}

func (s *recSink) has(set string, addr string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.ContainsFunc(s.elems, func(e dataplane.SetElement) bool {
		return string(e.Set) == set && e.Addr.String() == addr
	})
}

type bench struct {
	r          *Resolver
	sink       *recSink
	prot, fast *fakeDoH
	fast2      *fakeDoH
}

// newBench — защищённый набор из одного сервера, быстрый — из двух.
func newBench(t *testing.T) *bench {
	t.Helper()
	b := &bench{sink: &recSink{}, prot: newFakeDoH(t), fast: newFakeDoH(t), fast2: newFakeDoH(t)}
	roots := x509.NewCertPool()
	for _, f := range []*fakeDoH{b.prot, b.fast, b.fast2} {
		roots.AddCert(f.srv.Certificate())
	}
	ups := []coredns.Upstream{
		{Name: "prot", Pools: []coredns.Pool{coredns.PoolProtected}},
		{Name: "fast", Pools: []coredns.Pool{coredns.PoolFast}},
		{Name: "fast2", Pools: []coredns.Pool{coredns.PoolFast}},
	}
	h := coredns.NewHealth(coredns.DefaultHealthParams())
	pol, err := coredns.NewPolicy(ups, []string{"telegram.org"}, h, coredns.DefaultParams())
	if err != nil {
		t.Fatal(err)
	}
	rules := lists.NewRules()
	_ = rules.SetBuiltin(lists.Builtin())
	r, err := New(Config{
		Upstreams: []UpstreamSpec{{Name: "prot", URL: b.prot.srv.URL + "/dns-query"}, {Name: "fast", URL: b.fast.srv.URL + "/dns-query"}, {Name: "fast2", URL: b.fast2.srv.URL + "/dns-query"}},
		Policy:    pol, Health: h, Cache: coredns.NewCache(coredns.DefaultCacheParams(100)), Rules: rules,
		ClassSet:  func(model.RuleLayer, model.TrafficClass) string { return "" },
		SetTTLMin: 5 * time.Minute, SetTTLMax: 12 * time.Hour, Canary: true,
		Route: func(string, netip.Addr) (model.LinkID, dataplane.SetName, bool) {
			return "isp1", dataplane.DomainLinkSet(0), true
		},
		Sink:    b.sink,
		Dial:    func(model.LinkID) *net.Dialer { return &net.Dialer{Timeout: time.Second} },
		RootCAs: roots, Timeout: time.Second,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	r.SetIndex(coredns.NewSetIndex([]coredns.SetSpec{{Name: "tross_dp_steam_store_0", Domains: []string{"steampowered.com"}}}))
	t.Cleanup(r.Close)
	b.r = r
	return b
}

func mkQuery(t *testing.T, id uint16, name string, typ dnsmessage.Type, edns bool) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name + "."), Type: typ, Class: dnsmessage.ClassINET})
	if edns {
		_ = b.StartAdditionals()
		var rh dnsmessage.ResourceHeader
		_ = rh.SetEDNS0(1232, dnsmessage.RCodeSuccess, false)
		_ = b.OPTResource(rh, dnsmessage.OPTResource{})
	}
	out, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func parse(t *testing.T, resp []byte) dnsmessage.Message {
	t.Helper()
	var m dnsmessage.Message
	if err := m.Unpack(resp); err != nil {
		t.Fatalf("bad response: %v", err)
	}
	return m
}

var client = netip.MustParseAddr("192.168.77.10")

// Адреса — в множествах раньше, чем клиент получил ответ; второй запрос — из
// кэша, с ID клиента и уменьшенным сроком.
func TestSetsBeforeAnswerAndCache(t *testing.T) {
	b := newBench(t)
	b.fast.set("store.steampowered.com", fakeAnswer{addr: "203.0.113.7", ttl: 300})
	b.fast2.set("store.steampowered.com", fakeAnswer{addr: "203.0.113.7", ttl: 300})
	ctx := context.Background()
	resp := b.r.Handle(ctx, mkQuery(t, 7, "store.steampowered.com", dnsmessage.TypeA, false), client, 512)
	m := parse(t, resp)
	if m.ID != 7 || len(m.Answers) != 1 {
		t.Fatalf("answer: %+v", m)
	}
	if !b.sink.has("tross_dp_steam_store_0", "203.0.113.7") || !b.sink.has("tross_dl0", "203.0.113.7") {
		t.Errorf("sets not filled before the answer: %+v", b.sink.elems)
	}
	before := b.fast.hits.Load() + b.fast2.hits.Load()
	m = parse(t, b.r.Handle(ctx, mkQuery(t, 9, "store.steampowered.com", dnsmessage.TypeA, false), client, 512))
	if m.ID != 9 || b.fast.hits.Load()+b.fast2.hits.Load() != before {
		t.Errorf("second query must come from cache with the client id: id %d", m.ID)
	}
	if ttl := m.Answers[0].Header.TTL; ttl > 300 || ttl < 298 {
		t.Errorf("cached ttl %d", ttl)
	}
	if s := b.r.Stats(); s.Queries != 2 || s.CacheHits != 1 {
		t.Errorf("stats %+v", s)
	}
}

func TestLocalAnswers(t *testing.T) {
	b := newBench(t)
	ctx := context.Background()
	for name, want := range map[string]dnsmessage.RCode{
		"use-application-dns.net": dnsmessage.RCodeNameError,
		"printer":                 dnsmessage.RCodeNameError,
		"nas.lan":                 dnsmessage.RCodeNameError,
		"tv.home.arpa":            dnsmessage.RCodeNameError,
	} {
		if m := parse(t, b.r.Handle(ctx, mkQuery(t, 1, name, dnsmessage.TypeA, false), client, 512)); m.RCode != want {
			t.Errorf("%s: %v", name, m.RCode)
		}
	}
	if m := parse(t, b.r.Handle(ctx, mkQuery(t, 1, "example.com", dnsmessage.TypeAAAA, false), client, 512)); m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 0 {
		t.Errorf("AAAA must be empty: %+v", m)
	}
	if n := b.prot.hits.Load() + b.fast.hits.Load() + b.fast2.hits.Load(); n != 0 {
		t.Errorf("local names went upstream: %d requests", n)
	}
}

// Гонка: пустой ответ, пришедший первым, проигрывает ответу с адресом.
func TestRaceNonEmptyWins(t *testing.T) {
	b := newBench(t)
	b.fast.set("site.example", fakeAnswer{rcode: dnsmessage.RCodeNameError})
	b.fast2.set("site.example", fakeAnswer{addr: "198.51.100.5", delay: 40 * time.Millisecond})
	m := parse(t, b.r.Handle(context.Background(), mkQuery(t, 3, "site.example", dnsmessage.TypeA, false), client, 512))
	if m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 1 {
		t.Errorf("race: %v %+v — want the address", m.RCode, m.Answers)
	}
}

// Особо личное — только защищённым набором.
func TestSensitiveGoesProtected(t *testing.T) {
	b := newBench(t)
	b.prot.set("web.telegram.org", fakeAnswer{addr: "149.154.167.99"})
	m := parse(t, b.r.Handle(context.Background(), mkQuery(t, 4, "web.telegram.org", dnsmessage.TypeA, false), client, 512))
	if len(m.Answers) != 1 || b.prot.hits.Load() != 1 || b.fast.hits.Load()+b.fast2.hits.Load() != 0 {
		t.Errorf("answers %d, protected %d, fast %d", len(m.Answers), b.prot.hits.Load(), b.fast.hits.Load()+b.fast2.hits.Load())
	}
}

func TestServfailAndHealth(t *testing.T) {
	b := newBench(t)
	b.fast.set("down.example", fakeAnswer{rcode: dnsmessage.RCodeServerFailure})
	b.fast2.set("down.example", fakeAnswer{rcode: dnsmessage.RCodeServerFailure})
	m := parse(t, b.r.Handle(context.Background(), mkQuery(t, 5, "down.example", dnsmessage.TypeA, false), client, 512))
	if m.RCode != dnsmessage.RCodeServerFailure {
		t.Errorf("rcode %v", m.RCode)
	}
	failed := 0
	for _, s := range b.r.cfg.Health.Snapshot() {
		failed += int(s.Failed)
	}
	if failed != 2 {
		t.Errorf("health failures %d, want 2", failed)
	}
}

// Большой ответ клиенту без EDNS по UDP — «повтори по TCP».
func TestUDPTruncation(t *testing.T) {
	b := newBench(t)
	b.fast.set("big.example", fakeAnswer{addr: "198.51.100.9", extra: 5})
	b.fast2.set("big.example", fakeAnswer{addr: "198.51.100.9", extra: 5})
	ctx := context.Background()
	if m := parse(t, b.r.Handle(ctx, mkQuery(t, 6, "big.example", dnsmessage.TypeA, false), client, 512)); !m.Truncated || len(m.Answers) != 0 {
		t.Errorf("udp without edns: truncated %v, %d answers", m.Truncated, len(m.Answers))
	}
	if m := parse(t, b.r.Handle(ctx, mkQuery(t, 6, "big.example", dnsmessage.TypeA, true), client, 512)); m.Truncated {
		t.Error("edns 1232 fits the answer")
	}
	if m := parse(t, b.r.Handle(ctx, mkQuery(t, 6, "big.example", dnsmessage.TypeA, false), client, 0)); m.Truncated {
		t.Error("tcp is never truncated")
	}
}

func TestServeAndSelfCheck(t *testing.T) {
	b := newBench(t)
	l, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := netip.MustParseAddrPort(l.LocalAddr().String())
	l.Close()
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- b.r.Serve(ctx, []netip.AddrPort{addr}, ready) }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatal(err)
	}
	cctx, ccancel := context.WithTimeout(context.Background(), time.Second)
	defer ccancel()
	if err := SelfCheck(cctx, addr); err != nil {
		t.Errorf("selfcheck: %v", err)
	}
	// По TCP — то же.
	c, err := net.Dial("tcp4", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	q := mkQuery(t, 11, "use-application-dns.net", dnsmessage.TypeA, false)
	_, _ = c.Write(append([]byte{0, byte(len(q))}, q...))
	_ = c.SetDeadline(time.Now().Add(time.Second))
	var lb [2]byte
	if _, err := io.ReadFull(c, lb[:]); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, int(lb[0])<<8|int(lb[1]))
	_, _ = io.ReadFull(c, resp)
	c.Close()
	if m := parse(t, resp); m.ID != 11 || m.RCode != dnsmessage.RCodeNameError {
		t.Errorf("tcp: %+v", m.Header)
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("serve: %v", err)
	}
}

// Своё имя — устройствам дома свой адрес без похода наружу; снаружи — как
// обычное имя.
func TestOwnHosts(t *testing.T) {
	b := newBench(t)
	b.r.cfg.Hosts = map[string]netip.Addr{"mc.home.example": netip.MustParseAddr("192.168.77.50")}
	b.r.cfg.Home = []netip.Prefix{netip.MustParsePrefix("192.168.77.0/24")}
	ctx := context.Background()
	m := parse(t, b.r.Handle(ctx, mkQuery(t, 1, "mc.home.example", dnsmessage.TypeA, false), client, 512))
	if len(m.Answers) != 1 || m.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{192, 168, 77, 50} || !m.Authoritative {
		t.Errorf("home device: %+v", m)
	}
	if m := parse(t, b.r.Handle(ctx, mkQuery(t, 2, "mc.home.example", dnsmessage.TypeAAAA, false), client, 512)); m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 0 {
		t.Errorf("AAAA of own name: %+v", m)
	}
	if n := b.prot.hits.Load() + b.fast.hits.Load() + b.fast2.hits.Load(); n != 0 {
		t.Errorf("own name went upstream: %d", n)
	}
	outside := netip.MustParseAddr("203.0.113.9")
	if m := parse(t, b.r.Handle(ctx, mkQuery(t, 3, "mc.home.example", dnsmessage.TypeA, false), outside, 512)); m.RCode != dnsmessage.RCodeNameError {
		t.Errorf("outside client must get the public answer (fake: NXDOMAIN): %v", m.RCode)
	}
}

// Кандидат на обход: множества — от демона по ключу правила (шаблону
// списка), до ответа; домен вне списков хук не вызывает.
func TestBypassSetsBeforeAnswer(t *testing.T) {
	b := newBench(t)
	_ = b.r.cfg.Rules.SetOnline("lab", model.DomainRule{Purpose: model.PurposeBypass}, []lists.Entry{{Pattern: "blocked.example", Match: model.MatchSuffix}})
	var keys []string
	b.r.cfg.Bypass = func(key string, layer model.RuleLayer, name string, _ netip.Addr) []dataplane.SetName {
		keys = append(keys, key+"|"+string(layer)+"|"+name)
		return []dataplane.SetName{dataplane.DPISet(1)}
	}
	for _, f := range []*fakeDoH{b.fast, b.fast2} {
		f.set("www.blocked.example", fakeAnswer{addr: "203.0.113.20"})
		f.set("open.example", fakeAnswer{addr: "203.0.113.21"})
	}
	ctx := context.Background()
	if m := parse(t, b.r.Handle(ctx, mkQuery(t, 1, "www.blocked.example", dnsmessage.TypeA, false), client, 512)); len(m.Answers) != 1 {
		t.Fatalf("answer %+v", m)
	}
	if !b.sink.has("tross_dpi1", "203.0.113.20") {
		t.Errorf("bypass set not filled before the answer: %+v", b.sink.elems)
	}
	_ = b.r.Handle(ctx, mkQuery(t, 2, "open.example", dnsmessage.TypeA, false), client, 512)
	if want := []string{"blocked.example|online|www.blocked.example"}; !slices.Equal(keys, want) {
		t.Errorf("hook calls %v, want %v", keys, want)
	}
}
