//go:build linux && integration && extra

package linkmon

import (
	"context"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
)

// Разовая проверка DoH по умолчанию в настоящей сети: сертификаты серверов
// должны сходиться с их IP. Дополнительный тест (признак сборки extra,
// `scripts/lab-itest extra`): TROSS_REAL_NET_IFACE — интерфейс с выходом в
// интернет; три запроса, по одному на сервер.
func TestDefaultDoHRealNetwork(t *testing.T) {
	iface := os.Getenv("TROSS_REAL_NET_IFACE")
	if iface == "" {
		t.Fatal("set TROSS_REAL_NET_IFACE to query real DoH servers")
	}
	// Те же адреса, что monitor.http_check.dns по умолчанию (internal/config).
	for _, u := range []string{"https://1.1.1.1/dns-query", "https://8.8.4.4/dns-query", "https://9.9.9.9/dns-query"} {
		ap := netip.AddrPortFrom(netip.MustParseAddr(u[8:len(u)-len("/dns-query")]), 443)
		srv := DNSServer{Proto: DNSOverHTTPS, Addr: ap, URL: u}
		dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second, Control: sockopts(iface, 0)}
			return d.DialContext(ctx, network, addr)
		}
		r := &net.Resolver{PreferGo: true, Dial: resolverDial([]DNSServer{srv}, dial, nil, 5*time.Second)}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		start := time.Now()
		addrs, err := r.LookupNetIP(ctx, "ip4", "www.gstatic.com.")
		cancel()
		if err != nil || len(addrs) == 0 {
			t.Errorf("%s: %v %v", u, addrs, err)
			continue
		}
		t.Logf("measure: %s → %v in %v", u, addrs[0], time.Since(start).Round(time.Millisecond))
	}
}
