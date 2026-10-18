package daemon

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"tross/core/model"
	"tross/internal/api"
	"tross/internal/dataplane"
	"tross/internal/linkmon"
	"tross/internal/resolver"
)

// knownDoH — адреса известных DoH-сервисов: соединение устройства с ними
// на 443 — почти наверняка его собственный DNS мимо резолвера (только для
// наблюдения: ничего не блокируется).
var knownDoH = []string{
	"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "9.9.9.10", "9.9.9.11",
	"94.140.14.14", "94.140.15.15", "94.140.14.140", "94.140.14.141", "208.67.222.222", "208.67.220.220",
	"194.242.2.2", "45.90.28.0", "45.90.30.0", "76.76.2.0", "76.76.10.0", "185.222.222.222", "45.11.45.11",
	"77.88.8.8", "77.88.8.1", "86.54.11.100", "185.95.218.42", "185.95.218.43",
}

// encryptedDNS — устройства дома со своим зашифрованным DNS по снимку
// соединений: DoT — порт 853, DoH — известные адреса на 443.
func encryptedDNS(conns []dataplane.Connection, doh map[netip.Addr]bool) []api.EncryptedDNS {
	type key struct{ dev, kind string }
	dst := map[key][]string{}
	var order []key
	for _, c := range conns {
		if c.Class == "" || c.Proto != "tcp" && c.Proto != "udp" {
			continue // своё мини-ПК и входящие
		}
		kind := ""
		switch {
		case c.Dst.Port() == 853:
			kind = "dot"
		case c.Dst.Port() == 443 && doh[c.Dst.Addr()]:
			kind = "doh"
		default:
			continue
		}
		k := key{c.Src.Addr().String(), kind}
		if _, ok := dst[k]; !ok {
			order = append(order, k)
		}
		if d := c.Dst.String(); !slices.Contains(dst[k], d) {
			dst[k] = append(dst[k], d)
		}
	}
	out := make([]api.EncryptedDNS, 0, len(order))
	for _, k := range order {
		out = append(out, api.EncryptedDNS{Device: k.dev, Kind: k.kind, Destinations: dst[k]})
	}
	return out
}

// interceptCheck — перехватывает ли канал обычный DNS: запрос на адрес
// документации (в интернете никуда не ведёт) ответить может только тот, кто
// перехватывает порт 53 по пути. Имя — случайное в зоне .invalid.
type interceptCheck struct {
	mu      sync.Mutex
	results map[model.LinkID]api.LinkDNS
}

// interceptTarget — RFC 5737, TEST-NET-1.
var interceptTarget = netip.MustParseAddrPort("192.0.2.53:53")

const interceptEvery = 6 * time.Hour

func (ic *interceptCheck) run(ctx context.Context, mon linkmon.LinkMonitor, dial resolver.Dialer) {
	// Первая проверка — когда каналы успели подняться.
	t := time.NewTimer(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		for _, s := range mon.Snapshot() {
			if !s.Health.State.Usable() {
				continue
			}
			got := probeIntercept(ctx, dial(s.Link.ID), interceptTarget)
			ic.mu.Lock()
			ic.results[s.Link.ID] = api.LinkDNS{Link: s.Link.ID, Intercepted: &got, CheckedAt: time.Now()}
			ic.mu.Unlock()
		}
		t.Reset(interceptEvery)
	}
}

func probeIntercept(ctx context.Context, d *net.Dialer, target netip.AddrPort) bool {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: uint16(time.Now().UnixNano()), RecursionDesired: true})
	_ = b.StartQuestions()
	name := fmt.Sprintf("tross-check-%x.invalid.", time.Now().UnixNano())
	_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	q, err := b.Finish()
	if err != nil {
		return false
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	c, err := d.DialContext(cctx, "udp4", target.String())
	if err != nil {
		return false
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write(q); err != nil {
		return false
	}
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	return err == nil && n >= 12 && buf[0] == q[0] && buf[1] == q[1]
}

func (ic *interceptCheck) snapshot(links []model.LinkID) []api.LinkDNS {
	ic.mu.Lock()
	defer ic.mu.Unlock()
	out := make([]api.LinkDNS, 0, len(links))
	for _, l := range links {
		r, ok := ic.results[l]
		if !ok {
			r = api.LinkDNS{Link: l}
		}
		out = append(out, r)
	}
	return out
}

// dnsStatus — для /api/dns.
func (s *dnsService) dnsStatus(ctx context.Context, dbg *dnsDebug) api.DNSStatus {
	st := s.res.Stats()
	out := api.DNSStatus{Queries: st.Queries, CacheHits: st.CacheHits, Failures: st.Failures, AvgUpTime: st.AvgUpstream,
		Serving: "fallback", Upstreams: s.health.Snapshot()}
	s.mu.Lock()
	if s.up {
		out.Serving = "resolver"
	}
	s.mu.Unlock()
	ds := dbg.status()
	out.Debug = api.DNSDebug{Active: ds.Active, Until: ds.Until}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if conns, err := s.dp.Connections(cctx); err == nil {
		out.EncryptedDNS = encryptedDNS(conns, s.doh)
	}
	links := make([]model.LinkID, 0, len(s.linkIdx))
	for l := range s.linkIdx {
		links = append(links, l)
	}
	slices.SortFunc(links, func(a, b model.LinkID) int { return s.linkIdx[a] - s.linkIdx[b] })
	out.Links = s.intercept.snapshot(links)
	return out
}
