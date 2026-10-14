package linkmon

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
	"sync"
	"sync/atomic"
	"time"
)

// DNSProto — способ обращения к резолверу HTTP-проверки.
type DNSProto int

const (
	DNSPlain     DNSProto = iota // порт 53: UDP, при усечении — TCP
	DNSOverTLS                   // DoT
	DNSOverHTTPS                 // DoH
)

// DNSServer — резолвер по IP; сертификат DoT/DoH сверяется с этим адресом.
type DNSServer struct {
	Proto DNSProto
	Addr  netip.AddrPort
	URL   string // DoH
}

type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// resolverDial — Dial для net.Resolver (PreferGo): серверы по кругу. Для DoT и
// DoH отдаётся потоковое соединение — резолвер Go сам переходит на формат
// DNS-over-TCP (длина + сообщение), если соединение не PacketConn.
func resolverDial(servers []DNSServer, dial dialFunc, roots *x509.CertPool, timeout time.Duration) dialFunc {
	var next atomic.Uint32
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		srv := servers[int(next.Add(1))%len(servers)]
		switch srv.Proto {
		case DNSOverTLS:
			c, err := dial(ctx, "tcp4", srv.Addr.String())
			if err != nil {
				return nil, err
			}
			tc := tls.Client(c, tlsConfig(srv.Addr, roots))
			hctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			if err := tc.HandshakeContext(hctx); err != nil {
				c.Close()
				return nil, err
			}
			return tc, nil
		case DNSOverHTTPS:
			return newDoHConn(srv, dial, roots, timeout), nil
		}
		if network == "tcp" || network == "tcp4" {
			return dial(ctx, "tcp4", srv.Addr.String())
		}
		return dial(ctx, "udp4", srv.Addr.String())
	}
}

func tlsConfig(addr netip.AddrPort, roots *x509.CertPool) *tls.Config {
	// ServerName — IP: SNI не отправляется, сертификат проверяется по IP.
	return &tls.Config{ServerName: addr.Addr().String(), RootCAs: roots, MinVersion: tls.VersionTLS12}
}

// dohConn — DNS-over-TCP поверх DoH (RFC 8484): запрос, записанный резолвером
// (2 байта длины + сообщение), уходит POST'ом, ответ возвращается в том же
// формате. Одно соединение — один запрос-ответ за раз (как у резолвера Go).
type dohConn struct {
	srv     DNSServer
	client  *http.Client
	mu      sync.Mutex
	out     bytes.Buffer
	in      bytes.Buffer
	dead    time.Time
	timeout time.Duration
}

const maxDNSMessage = 64 << 10

func newDoHConn(srv DNSServer, dial dialFunc, roots *x509.CertPool, timeout time.Duration) *dohConn {
	tr := &http.Transport{
		DialContext:         func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx, "tcp4", srv.Addr.String()) },
		TLSClientConfig:     tlsConfig(srv.Addr, roots),
		TLSHandshakeTimeout: timeout,
		DisableKeepAlives:   true,
		// Свой DialContext и TLSClientConfig иначе выключают HTTP/2, а часть
		// серверов (Quad9) отвечает на HTTP/1.1 ошибкой 505.
		ForceAttemptHTTP2: true,
	}
	return &dohConn{srv: srv, client: &http.Client{Transport: tr, Timeout: timeout}, timeout: timeout}
}

func (c *dohConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.out.Write(b)
	return len(b), nil
}

func (c *dohConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.in.Len() == 0 {
		if err := c.roundTrip(); err != nil {
			return 0, err
		}
	}
	return c.in.Read(b)
}

func (c *dohConn) roundTrip() error {
	raw := c.out.Bytes()
	if len(raw) < 2 || int(binary.BigEndian.Uint16(raw)) != len(raw)-2 {
		return errors.New("doh: incomplete query")
	}
	msg := bytes.Clone(raw[2:])
	c.out.Reset()
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	if !c.dead.IsZero() {
		ctx, cancel = context.WithDeadline(context.Background(), c.dead)
	}
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.srv.URL, bytes.NewReader(msg))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("doh %s: status %d", c.srv.Addr, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDNSMessage+1))
	if err != nil {
		return err
	}
	if len(body) == 0 || len(body) > maxDNSMessage {
		return fmt.Errorf("doh %s: bad response size %d", c.srv.Addr, len(body))
	}
	var n [2]byte
	binary.BigEndian.PutUint16(n[:], uint16(len(body)))
	c.in.Write(n[:])
	c.in.Write(body)
	return nil
}

func (c *dohConn) Close() error { return nil }

func (c *dohConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.dead = t
	c.mu.Unlock()
	return nil
}
func (c *dohConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *dohConn) SetWriteDeadline(t time.Time) error { return nil }
func (c *dohConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *dohConn) RemoteAddr() net.Addr               { return net.TCPAddrFromAddrPort(c.srv.Addr) }
