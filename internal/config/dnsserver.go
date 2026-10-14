package config

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"go.yaml.in/yaml/v3"
)

// DNSProto — способ обращения к резолверу.
type DNSProto string

const (
	DNSPlain     DNSProto = "udp"   // обычный DNS, порт 53 (UDP, при усечении — TCP)
	DNSOverTLS   DNSProto = "tls"   // DoT
	DNSOverHTTPS DNSProto = "https" // DoH
)

// DNSServer — резолвер HTTP-проверки: «1.1.1.1» или «udp://1.1.1.1» —
// обычный DNS, «tls://1.1.1.1[:853]» — DoT, «https://1.1.1.1/dns-query» —
// DoH. Только IPv4-адрес, не имя: проверке нельзя зависеть от DNS, чтобы
// найти свой DNS; сертификат DoT/DoH сверяется с этим адресом.
type DNSServer struct {
	Proto DNSProto
	Addr  netip.AddrPort
	URL   string // DoH: адрес запроса
	raw   string
}

func (d DNSServer) String() string { return d.raw }

func (d *DNSServer) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	v, err := ParseDNSServer(s)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*d = v
	return nil
}

func ParseDNSServer(s string) (DNSServer, error) {
	bad := func(why string) (DNSServer, error) {
		return DNSServer{}, fmt.Errorf("dns server %q: %s", s, why)
	}
	if !strings.Contains(s, "://") {
		s = "udp://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return bad("want IPv4, udp://IPv4, tls://IPv4[:port] or https://IPv4[:port]/path")
	}
	proto, port := DNSProto(u.Scheme), uint16(0)
	switch proto {
	case DNSPlain:
		port = 53
	case DNSOverTLS:
		port = 853
	case DNSOverHTTPS:
		port = 443
		if u.Path == "" || u.Path == "/" {
			return bad("DoH needs a path, e.g. /dns-query")
		}
	default:
		return bad("scheme must be udp, tls or https")
	}
	if proto != DNSOverHTTPS && (u.Path != "" || u.RawQuery != "") {
		return bad("only https:// takes a path")
	}
	a, err := netip.ParseAddr(u.Hostname())
	if err != nil {
		return bad("use an IP address, not a name")
	}
	if !a.Is4() {
		return bad("only IPv4 is supported")
	}
	if p := u.Port(); p != "" {
		var n uint16
		if _, err := fmt.Sscan(p, &n); err != nil || n == 0 {
			return bad("bad port")
		}
		port = n
	}
	d := DNSServer{Proto: proto, Addr: netip.AddrPortFrom(a, port), raw: strings.TrimPrefix(s, "udp://")}
	if proto == DNSOverHTTPS {
		d.URL = u.String()
	}
	return d, nil
}

func dnsServers(s ...string) []DNSServer {
	out := make([]DNSServer, len(s))
	for i, v := range s {
		d, err := ParseDNSServer(v)
		if err != nil {
			panic(err)
		}
		out[i] = d
	}
	return out
}
