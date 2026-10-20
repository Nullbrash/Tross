package resolver

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"time"

	"tross/core/model"
)

// Dialer — сокет через канал (метка канала, привязка к интерфейсу).
type Dialer func(link model.LinkID) *net.Dialer

// lookupFunc — адреса имени сервера через свои серверы, заданные по IP:
// системный DNS мини-ПК — это мы же.
type lookupFunc func(ctx context.Context, host string, link model.LinkID) ([]netip.Addr, error)

// upstream — внешний сервер: DoH (https://) или DoT (tls://). Соединения —
// свои на каждый канал, переиспользуются: рукопожатие TLS дороже запроса.
type upstream struct {
	name    string
	doh     bool
	url     string
	host    string // IP или имя из адреса
	port    string
	tls     *tls.Config
	dial    Dialer
	lookup  lookupFunc
	timeout time.Duration

	mu      sync.Mutex
	clients map[model.LinkID]*http.Client
	idle    map[model.LinkID][]*tls.Conn
}

// tlsName — имя, по которому проверяется сертификат сервера, заданного по
// IP, если в сертификате нет IP (имя при этом не отправляется).
func newUpstream(name, raw, tlsName string, roots tlsRoots, dial Dialer, lookup lookupFunc, timeout time.Duration) (*upstream, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("upstream %s: bad url %q", name, raw)
	}
	up := &upstream{name: name, url: raw, host: u.Hostname(), dial: dial, lookup: lookup, timeout: timeout,
		clients: map[model.LinkID]*http.Client{}, idle: map[model.LinkID][]*tls.Conn{}}
	switch u.Scheme {
	case "https":
		up.doh, up.port = true, u.Port()
		if up.port == "" {
			up.port = "443"
		}
	case "tls":
		up.port = u.Port()
		if up.port == "" {
			up.port = "853"
		}
	default:
		return nil, fmt.Errorf("upstream %s: want https:// or tls://, got %q", name, raw)
	}
	// Для адреса-IP Go не отправляет имя (SNI) и сверяет IP в сертификате:
	// провайдер канала не видит, к какому DNS-сервису идёт запрос.
	up.tls = &tls.Config{ServerName: up.host, RootCAs: roots.pool, MinVersion: tls.VersionTLS12}
	if tlsName != "" {
		// Имя в SNI в России обрывают — сертификат проверяется по имени
		// вручную, а наружу уходит только IP.
		up.tls.InsecureSkipVerify = true
		up.tls.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no server certificate")
			}
			inter := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				inter.AddCert(c)
			}
			_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{DNSName: tlsName, Roots: roots.pool, Intermediates: inter})
			return err
		}
	}
	if up.doh {
		up.tls.NextProtos = []string{"h2", "http/1.1"}
	}
	return up, nil
}

// connect — TCP через канал к серверу; имя — через lookup.
func (u *upstream) connect(ctx context.Context, link model.LinkID) (net.Conn, error) {
	addrs := []string{u.host}
	if _, err := netip.ParseAddr(u.host); err != nil {
		ips, err := u.lookup(ctx, u.host, link)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("resolve %s: %v", u.host, err)
		}
		addrs = addrs[:0]
		for _, ip := range ips {
			addrs = append(addrs, ip.String())
		}
	}
	var errs []error
	for _, a := range addrs {
		c, err := u.dial(link).DialContext(ctx, "tcp", net.JoinHostPort(a, u.port))
		if err == nil {
			return c, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

func (u *upstream) exchange(ctx context.Context, link model.LinkID, q []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, u.timeout)
	defer cancel()
	if u.doh {
		return u.exchangeDoH(ctx, link, q)
	}
	return u.exchangeDoT(ctx, link, q)
}

func (u *upstream) client(link model.LinkID) *http.Client {
	u.mu.Lock()
	defer u.mu.Unlock()
	if c := u.clients[link]; c != nil {
		return c
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return u.connect(ctx, link)
		},
		TLSClientConfig:     u.tls,
		ForceAttemptHTTP2:   true,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: u.timeout,
	}
	c := &http.Client{Transport: tr}
	u.clients[link] = c
	return c
}

func (u *upstream) exchangeDoH(ctx context.Context, link model.LinkID, q []byte) ([]byte, error) {
	// ID 0 — так советует RFC 8484 (кэшируемость у сервера); свой ID
	// резолвер ставит клиенту сам.
	q = append([]byte(nil), q...)
	binary.BigEndian.PutUint16(q, 0)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.url, bytes.NewReader(q))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := u.client(link).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh %s: http %d", u.name, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 65535))
}

func (u *upstream) exchangeDoT(ctx context.Context, link model.LinkID, q []byte) ([]byte, error) {
	c, err := u.dotConn(ctx, link)
	if err != nil {
		return nil, err
	}
	resp, err := dotRoundTrip(ctx, c, q)
	if err != nil {
		c.Close()
		return nil, err
	}
	u.mu.Lock()
	if len(u.idle[link]) < 2 {
		u.idle[link] = append(u.idle[link], c)
	} else {
		c.Close()
	}
	u.mu.Unlock()
	return resp, nil
}

func (u *upstream) dotConn(ctx context.Context, link model.LinkID) (*tls.Conn, error) {
	u.mu.Lock()
	if n := len(u.idle[link]); n > 0 {
		c := u.idle[link][n-1]
		u.idle[link] = u.idle[link][:n-1]
		u.mu.Unlock()
		return c, nil
	}
	u.mu.Unlock()
	raw, err := u.connect(ctx, link)
	if err != nil {
		return nil, err
	}
	c := tls.Client(raw, u.tls)
	if err := c.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return c, nil
}

// dotRoundTrip — запрос и ответ в одном соединении (длина + сообщение); ответ
// — тот, чей ID совпал.
func dotRoundTrip(ctx context.Context, c net.Conn, q []byte) ([]byte, error) {
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	msg := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(msg, uint16(len(q)))
	copy(msg[2:], q)
	if _, err := c.Write(msg); err != nil {
		return nil, err
	}
	for {
		var l [2]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return nil, err
		}
		resp := make([]byte, binary.BigEndian.Uint16(l[:]))
		if _, err := io.ReadFull(c, resp); err != nil {
			return nil, err
		}
		if len(resp) >= 2 && binary.BigEndian.Uint16(resp) == binary.BigEndian.Uint16(q) {
			return resp, nil
		}
	}
}

// close — закрыть соединения (остановка резолвера).
func (u *upstream) close() {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, c := range u.clients {
		c.CloseIdleConnections()
	}
	for _, cs := range u.idle {
		for _, c := range cs {
			c.Close()
		}
	}
	u.idle = map[model.LinkID][]*tls.Conn{}
}
