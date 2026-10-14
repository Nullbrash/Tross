package linkmon

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var testAnswer = netip.MustParseAddr("192.0.2.7")

// answerA — тестовый резолвер: на A — testAnswer, на прочее — пустой ответ.
func answerA(t *testing.T, query []byte) []byte {
	t.Helper()
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil {
		t.Errorf("bad query: %v", err)
		return nil
	}
	q, err := p.Question()
	if err != nil {
		t.Errorf("bad question: %v", err)
		return nil
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionAvailable: true})
	_ = b.StartQuestions()
	_ = b.Question(q)
	_ = b.StartAnswers()
	if q.Type == dnsmessage.TypeA {
		_ = b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
			dnsmessage.AResource{A: testAnswer.As4()})
	}
	out, err := b.Finish()
	if err != nil {
		t.Errorf("build answer: %v", err)
	}
	return out
}

func plainDial(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

func lookup(t *testing.T, servers []DNSServer, roots *x509.CertPool) ([]netip.Addr, error) {
	t.Helper()
	r := &net.Resolver{PreferGo: true, Dial: resolverDial(servers, plainDial, roots, 2*time.Second)}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return r.LookupNetIP(ctx, "ip4", "check.example.")
}

func tlsServer(t *testing.T) (*httptest.Server, *x509.CertPool) { return tlsServerProto(t, false) }

// tlsServerProto — DoH-сервер; h2only — как Quad9: на HTTP/1.1 отвечает 505.
func tlsServerProto(t *testing.T, h2only bool) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h2only && r.ProtoMajor < 2 {
			http.Error(w, "HTTP/2 required", http.StatusHTTPVersionNotSupported)
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/dns-query" || r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		q, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(answerA(t, q))
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	// Отказы рукопожатия в проверке с недоверенным корнем — ожидаемы.
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	return srv, roots
}

func TestResolveOverHTTPS(t *testing.T) {
	srv, roots := tlsServer(t)
	ap := netip.MustParseAddrPort(strings.TrimPrefix(srv.URL, "https://"))
	doh := []DNSServer{{Proto: DNSOverHTTPS, Addr: ap, URL: srv.URL + "/dns-query"}}
	got, err := lookup(t, doh, roots)
	if err != nil || len(got) != 1 || got[0] != testAnswer {
		t.Fatalf("DoH lookup = %v, %v; want %v", got, err, testAnswer)
	}
	// Сертификат не от доверенного корня — ответа нет (подмена не принимается).
	if got, err := lookup(t, doh, x509.NewCertPool()); err == nil {
		t.Fatalf("DoH with untrusted certificate resolved: %v", got)
	}
}

func TestResolveOverHTTPSRequiresHTTP2(t *testing.T) {
	srv, roots := tlsServerProto(t, true)
	ap := netip.MustParseAddrPort(strings.TrimPrefix(srv.URL, "https://"))
	got, err := lookup(t, []DNSServer{{Proto: DNSOverHTTPS, Addr: ap, URL: srv.URL + "/dns-query"}}, roots)
	if err != nil || len(got) != 1 || got[0] != testAnswer {
		t.Fatalf("DoH to an HTTP/2-only server = %v, %v; want %v", got, err, testAnswer)
	}
}

func TestResolveOverTLS(t *testing.T) {
	srv, roots := tlsServer(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: srv.TLS.Certificates})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				for {
					var n [2]byte
					if _, err := io.ReadFull(c, n[:]); err != nil {
						return
					}
					q := make([]byte, binary.BigEndian.Uint16(n[:]))
					if _, err := io.ReadFull(c, q); err != nil {
						return
					}
					a := answerA(t, q)
					binary.BigEndian.PutUint16(n[:], uint16(len(a)))
					_, _ = c.Write(append(n[:], a...))
				}
			}()
		}
	}()
	dot := []DNSServer{{Proto: DNSOverTLS, Addr: netip.MustParseAddrPort(ln.Addr().String())}}
	got, err := lookup(t, dot, roots)
	if err != nil || len(got) != 1 || got[0] != testAnswer {
		t.Fatalf("DoT lookup = %v, %v; want %v", got, err, testAnswer)
	}
}

func TestResolvePlain(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(answerA(t, buf[:n]), addr)
		}
	}()
	plain := []DNSServer{{Proto: DNSPlain, Addr: netip.MustParseAddrPort(pc.LocalAddr().String())}}
	got, err := lookup(t, plain, nil)
	if err != nil || len(got) != 1 || got[0] != testAnswer {
		t.Fatalf("plain lookup = %v, %v; want %v", got, err, testAnswer)
	}
}
