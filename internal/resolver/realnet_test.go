//go:build realnet

// Разовая проверка в настоящей сети (запуск вручную, на отдельной машине):
// серверы DNS по умолчанию через DoH/DoT — задержка и ответы;
// узлы Steam через защищённый и быстрый наборы — не уводит ли защищённый
// загрузки на дальние узлы. Запросы — последовательно, один раз.
//
//	go test -tags realnet -run TestRealNetwork -v ./internal/resolver/
package resolver

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"tross/core/model"
	"tross/internal/config"
)

var realNames = []string{
	"example.com", "wikipedia.org", "github.com", "debian.org", "kernel.org", "mozilla.org",
	"microsoft.com", "apple.com", "cloudflare.com", "google.com", "vk.com", "ok.ru",
	"gosuslugi.ru", "habr.com", "telegram.org", "discord.com", "youtube.com", "linkedin.com",
}

var steamNames = []string{
	"store.steampowered.com", "media.steampowered.com", "cdn.steamstatic.com", "cdn.akamai.steamstatic.com",
	"cdn.cloudflare.steamstatic.com", "clientconfig.akamai.steamstatic.com", "steampipe.akamaized.net", "lancache.steamcontent.com",
}

func realQuery(t *testing.T, u *upstream, name string) ([]netip.Addr, time.Duration, error) {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: randomID(), RecursionDesired: true})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name + "."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	q, _ := b.Finish()
	start := time.Now()
	raw, err := u.exchange(context.Background(), "home", q)
	took := time.Since(start)
	if err != nil {
		return nil, took, err
	}
	var m dnsmessage.Message
	if err := m.Unpack(raw); err != nil {
		return nil, took, err
	}
	if m.RCode != dnsmessage.RCodeSuccess {
		return nil, took, fmt.Errorf("rcode %v", m.RCode)
	}
	var out []netip.Addr
	for _, a := range m.Answers {
		if r, ok := a.Body.(*dnsmessage.AResource); ok {
			out = append(out, netip.AddrFrom4(r.A))
		}
	}
	return out, took, nil
}

func TestRealNetwork(t *testing.T) {
	dial := func(model.LinkID) *net.Dialer { return &net.Dialer{Timeout: 3 * time.Second} }
	ups := map[string]*upstream{}
	var order []string
	for _, c := range config.DefaultUpstreams() {
		u, err := newUpstream(c.Name, c.URL, c.TLSName, tlsRoots{}, dial, nil, 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		ups[c.Name], order = u, append(order, c.Name)
		defer u.close()
	}

	// REALNET_ONLY — перепроверка только этих серверов (через запятую).
	only := map[string]bool{}
	for _, n := range strings.Split(os.Getenv("REALNET_ONLY"), ",") {
		if n != "" {
			only[n] = true
		}
	}
	skip := func(n string) bool { return len(only) > 0 && !only[n] }
	t.Log("== DNS servers: 18 names each, sequential")
	for _, n := range order {
		if skip(n) {
			continue
		}
		var lat []time.Duration
		var fails []string
		empty := 0
		for _, name := range realNames {
			addrs, took, err := realQuery(t, ups[n], name)
			if err != nil {
				fails = append(fails, name+": "+err.Error())
				continue
			}
			lat = append(lat, took)
			if len(addrs) == 0 {
				empty++
			}
		}
		slices.Sort(lat)
		med, worst := time.Duration(0), time.Duration(0)
		if len(lat) > 0 {
			med, worst = lat[len(lat)/2], lat[len(lat)-1]
		}
		t.Logf("%-17s %-34s ok %2d/%d, no A %d, median %v, max %v %s", n, ups[n].url, len(lat), len(realNames), empty,
			med.Round(time.Millisecond), worst.Round(time.Millisecond), strings.Join(fails, "; "))
	}

	t.Log("== Steam: addresses via the protected and the fast set, TCP 443 connect ×3 to the first address")
	pools := map[string][]string{"protected": {"quad9", "mullvad", "digitale", "dns4eu"}, "fast": {"cloudflare", "google"}}
	rtt := map[netip.Addr]time.Duration{}
	for _, name := range steamNames {
		for _, pool := range []string{"protected", "fast"} {
			var firsts []string
			for _, n := range pools[pool] {
				if skip(n) {
					continue
				}
				addrs, _, err := realQuery(t, ups[n], name)
				if err != nil || len(addrs) == 0 {
					firsts = append(firsts, n+"=-")
					continue
				}
				a := addrs[0]
				if _, ok := rtt[a]; !ok {
					rtt[a] = connectRTT(a)
				}
				firsts = append(firsts, fmt.Sprintf("%s=%v (%v)", n, a, rtt[a].Round(time.Millisecond)))
			}
			if len(firsts) > 0 {
				t.Logf("%-36s %-9s %s", name, pool, strings.Join(firsts, ", "))
			}
		}
	}
}

// connectRTT — лучшее из трёх TCP-подключений к :443 (без передачи данных).
func connectRTT(a netip.Addr) time.Duration {
	best := time.Duration(0)
	for range 3 {
		start := time.Now()
		c, err := net.DialTimeout("tcp", netip.AddrPortFrom(a, 443).String(), 3*time.Second)
		if err != nil {
			continue
		}
		d := time.Since(start)
		c.Close()
		if best == 0 || d < best {
			best = d
		}
	}
	return best
}
