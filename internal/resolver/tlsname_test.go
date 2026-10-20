package resolver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"tross/core/model"
)

// Сертификат сервера выдан только на имя: с tls_name сервер по IP
// проверяется по имени, а имя в SNI не уходит; без него или с чужим именем
// — отказ.
func TestTLSNameWithoutSNI(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{"dns.lab.example"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	var mu sync.Mutex
	var snis []string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q, _ := io.ReadAll(r.Body)
		q[2] |= 0x80 // ответ: тот же вопрос без записей
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(q)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			mu.Lock()
			snis = append(snis, h.ServerName)
			mu.Unlock()
			return nil, nil
		},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	ask := func(name string) error {
		u, err := newUpstream("x", srv.URL+"/dns-query", name, tlsRoots{roots},
			func(model.LinkID) *net.Dialer { return &net.Dialer{Timeout: time.Second} }, nil, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer u.close()
		_, err = u.exchange(context.Background(), "isp1", mkQuery(t, 1, "a.example", dnsmessage.TypeA, false))
		return err
	}
	if err := ask(""); err == nil {
		t.Error("certificate without the IP accepted with no tls_name")
	}
	if err := ask("dns.lab.example"); err != nil {
		t.Errorf("tls_name: %v", err)
	}
	if err := ask("other.example"); err == nil {
		t.Error("wrong tls_name accepted")
	}
	mu.Lock()
	defer mu.Unlock()
	for _, s := range snis {
		if s != "" {
			t.Errorf("SNI sent: %q", s)
		}
	}
}
