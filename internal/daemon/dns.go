package daemon

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/netip"
	"net/url"
	"os"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"

	"tross/core/classify"
	"tross/core/decision"
	coredns "tross/core/dns"
	"tross/core/event"
	"tross/core/lists"
	"tross/core/model"
	"tross/core/profile"
	"tross/internal/api"
	"tross/internal/config"
	"tross/internal/dataplane"
	"tross/internal/resolver"
)

// pinsEvery — закрепления из ядра читаются не чаще: чтение множеств nft —
// десятки мс, а резолверу на каждый промах кэша.
const pinsEvery = 3 * time.Second

// dnsService — резолвер дома: запуск, переключение перехвата, сторож (D-19),
// канал по домену (DNS тем же путём, что и трафик).
type dnsService struct {
	log      *slog.Logger
	dp       dataplane.Dataplane
	bus      event.EventBus
	res      *resolver.Resolver
	listen   []netip.AddrPort
	every    time.Duration
	failures int
	cls      *classify.Engine
	plan     func() []decision.ClassPlan
	linkIdx  map[model.LinkID]int
	health   *coredns.Health
	dial     resolver.Dialer
	// doh — адреса DoH-сервисов: известные и свои серверы (наблюдение).
	doh       map[netip.Addr]bool
	intercept *interceptCheck

	mu     sync.Mutex
	up     bool
	pins   []dataplane.Pin
	pinsAt time.Time
}

func newDNSService(cfg *config.Config, log *slog.Logger, dp dataplane.Dataplane, bus event.EventBus, spec dataplane.Spec, cat profile.Catalog, cls *classify.Engine, rules *lists.Rules, plan func() []decision.ClassPlan) (*dnsService, error) {
	s := &dnsService{log: log, dp: dp, bus: bus, every: cfg.DNS.Watchdog.Interval, failures: cfg.DNS.Watchdog.Failures,
		cls: cls, plan: plan, linkIdx: map[model.LinkID]int{}}
	for _, l := range cfg.DNS.Listen {
		ap, err := netip.ParseAddrPort(l)
		if err != nil {
			return nil, err
		}
		s.listen = append(s.listen, ap)
	}
	nets := map[model.LinkID]resolver.LinkNet{}
	for i, l := range spec.Links {
		s.linkIdx[l.Link.ID] = i
		nets[l.Link.ID] = resolver.LinkNet{Interface: l.Link.Interface, Mark: l.FwMark}
	}
	health := coredns.NewHealth(coredns.DefaultHealthParams())
	s.health, s.dial = health, resolver.LinkDialer(nets, 3*time.Second)
	s.intercept = &interceptCheck{results: map[model.LinkID]api.LinkDNS{}}
	s.doh = map[netip.Addr]bool{}
	for _, a := range knownDoH {
		s.doh[netip.MustParseAddr(a)] = true
	}
	for _, u := range cfg.DNS.Upstreams {
		if uu, err := url.Parse(u.URL); err == nil {
			if a, err := netip.ParseAddr(uu.Hostname()); err == nil {
				s.doh[a] = true
			}
		}
	}
	pol, err := coredns.NewPolicy(cfg.DNS.PolicyUpstreams(), sensitiveDomains(cfg, cat), health, cfg.DNS.PolicyParams())
	if err != nil {
		return nil, err
	}
	var roots *x509.CertPool
	if cfg.DNS.CAFile != "" {
		pem, err := os.ReadFile(cfg.DNS.CAFile)
		if err != nil {
			return nil, fmt.Errorf("dns.ca_file: %w", err)
		}
		if roots, err = x509.SystemCertPool(); err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("dns.ca_file: no certificates")
		}
	}
	var ups []resolver.UpstreamSpec
	for _, u := range cfg.DNS.Upstreams {
		ups = append(ups, resolver.UpstreamSpec{Name: u.Name, URL: u.URL})
	}
	s.res, err = resolver.New(resolver.Config{
		Upstreams: ups, Policy: pol, Health: health,
		Cache: coredns.NewCache(coredns.DefaultCacheParams(cfg.DNS.CacheSize)), Rules: rules,
		ClassSet:  func(l model.RuleLayer, c model.TrafficClass) string { return string(dataplane.ListSet(l, c)) },
		SetTTLMin: cfg.DNS.SetTTL.Min, SetTTLMax: cfg.DNS.SetTTL.Max, Canary: *cfg.DNS.FirefoxCanaryNXDomain,
		Route: s.route, Sink: dp, Dial: s.dial, RootCAs: roots, Log: log,
		Hosts: cfg.DNS.Hosts, Home: cfg.LAN.Networks,
	})
	if err != nil {
		return nil, err
	}
	s.res.SetIndex(coredns.NewSetIndex(spec.Classify.DomainSpecs()))
	return s, nil
}

// sensitiveDomains — особо личное: домены из конфига и сервисов каталога.
func sensitiveDomains(cfg *config.Config, cat profile.Catalog) []string {
	out := append([]string(nil), cfg.DNS.Sensitive.Domains...)
	for _, ref := range cfg.DNS.Sensitive.Services {
		d, _ := cat.Domains(ref)
		out = append(out, d...)
	}
	return out
}

// run — резолвер до отмены ctx. Перехват DNS переводится на резолвер только
// когда он слушает, и обратно на запасной — до того, как он замолчит.
func (s *dnsService) run(ctx context.Context) {
	defer s.res.Close()
	sctx, stop := context.WithCancel(context.Background())
	defer stop()
	ready := make(chan struct{})
	served := make(chan error, 1)
	go func() { served <- s.res.Serve(sctx, s.listen, ready) }()
	select {
	case <-ready:
		s.setUp(ctx, true, "resolver listening")
	case err := <-served:
		// Резолвер не запустился (адрес занят): дом остаётся на запасном —
		// демон работает дальше (fail-open).
		s.log.Error("dns resolver not started, home DNS stays on the fallback resolver", "err", err)
		s.publish("resolver failed to start: " + err.Error())
		return
	case <-ctx.Done():
		return
	}
	t := time.NewTicker(s.every)
	defer t.Stop()
	fails := 0
	for {
		select {
		case <-ctx.Done():
			tctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			s.setUp(tctx, false, "daemon stopping")
			cancel()
			stop()
			<-served
			return
		case <-t.C:
		}
		cctx, cancel := context.WithTimeout(ctx, min(s.every, 2*time.Second))
		err := resolver.SelfCheck(cctx, s.listen[0])
		cancel()
		switch {
		case err != nil:
			fails++
			if fails >= s.failures {
				s.setUp(ctx, false, fmt.Sprintf("resolver not answering (%d checks): %v", fails, err))
			}
		default:
			fails = 0
			s.setUp(ctx, true, "resolver answers again")
		}
	}
}

func (s *dnsService) setUp(ctx context.Context, up bool, why string) {
	s.mu.Lock()
	changed := s.up != up
	s.up = up
	s.mu.Unlock()
	if !changed {
		return
	}
	if err := s.dp.SetDNS(ctx, up); err != nil {
		s.log.Error("dns interception switch failed", "up", up, "err", err)
		return
	}
	target := "fallback resolver"
	if up {
		target = "daemon resolver"
	}
	s.log.Info("home dns", "to", target, "why", why)
	s.publish(target + ": " + why)
}

func (s *dnsService) publish(msg string) {
	s.bus.Publish(event.Event{Topic: event.TopicDNSWatchdog, Data: msg})
}

// route — канал домена (вопрос 3 плана, вариант (а)): среди долей плана его
// класса — постоянный для сайта (зарегистрированный домен; у частей с
// закреплением сервиса — для всего сервиса), весами плана; DNS спрашивается
// через канал закрепления устройства, если оно есть.
func (s *dnsService) route(domain string, client netip.Addr) (model.LinkID, dataplane.SetName, bool) {
	c := s.cls.Classify(model.Flow{Src: netip.AddrPortFrom(client, 0), Domain: domain})
	plans := s.plan()
	var cp decision.ClassPlan
	for _, p := range plans {
		if p.Class == c.Class {
			cp = p
		}
	}
	shares := positive(cp.Shares)
	if len(shares) == 0 {
		// Классу некуда (его каналы упали) — DNS всё равно нужен: любой
		// канал из плана; соединение ядро сам отклонит или уведёт.
		for _, p := range plans {
			if len(positive(p.Shares)) > 0 {
				shares = positive(p.Shares)
				break
			}
		}
	}
	if len(shares) == 0 {
		return "", "", false
	}
	key, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		key = domain
	}
	if c.PinService && c.Service != "" {
		key = "service:" + c.Service
	}
	link := weightedChoice(key, shares)
	query := link
	if p, ok := s.devicePin(client, c); ok {
		query = p
	}
	var pin dataplane.SetName
	if len(shares) > 1 {
		pin = dataplane.DomainLinkSet(s.linkIdx[link])
	}
	return query, pin, true
}

func positive(shares []decision.LinkShare) []decision.LinkShare {
	var out []decision.LinkShare
	for _, s := range shares {
		if s.Weight > 0 {
			out = append(out, s)
		}
	}
	return out
}

// weightedChoice — взвешенный rendezvous hashing: тот же ключ — тот же канал,
// пока канал в плане; уход канала переносит только его ключи.
func weightedChoice(key string, shares []decision.LinkShare) model.LinkID {
	best, bestScore := shares[0].Link, math.Inf(-1)
	for _, s := range shares {
		u := (float64(coredns.Score(key, string(s.Link))>>11) + 1) / (1 << 53)
		if score := float64(s.Weight) / -math.Log(u); score > bestScore {
			best, bestScore = s.Link, score
		}
	}
	return best
}

// devicePin — канал, за которым ядро держит устройство в этом классе или
// сервисе.
func (s *dnsService) devicePin(client netip.Addr, c model.Classification) (model.LinkID, bool) {
	s.mu.Lock()
	if time.Since(s.pinsAt) > pinsEvery {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		pins, err := s.dp.Pins(ctx)
		cancel()
		if err == nil {
			s.pins = pins
		}
		s.pinsAt = time.Now()
	}
	pins := s.pins
	s.mu.Unlock()
	for _, p := range pins {
		if p.Device != client || p.Dst.IsValid() {
			continue
		}
		if c.PinService && c.Service != "" && p.Service == c.Service || p.Service == "" && p.Class == c.Class {
			return p.Link, true
		}
	}
	return "", false
}
