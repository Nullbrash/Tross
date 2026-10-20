package tlsca

import (
	"crypto/x509"
	"encoding/pem"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func cfg(dir string) Config {
	return Config{Dir: dir, Names: []string{"tross.lan"}, Addrs: []netip.Addr{netip.MustParseAddr("192.168.10.1")},
		Networks: []netip.Prefix{netip.MustParsePrefix("192.168.10.0/24")}}
}

func TestCAIssueAndVerify(t *testing.T) {
	dir := t.TempDir()
	ca, err := Load(cfg(dir))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := ca.Server()
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca.CAPEM()) {
		t.Fatal("ca pem")
	}
	for _, name := range []string{"tross.lan", "192.168.10.1"} {
		if _, err := srv.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: name}); err != nil {
			t.Errorf("verify %s: %v", name, err)
		}
	}
	if fi, _ := os.Stat(filepath.Join(dir, "ca.key")); fi.Mode().Perm() != 0o600 && os.PathSeparator == '/' {
		t.Errorf("ca.key mode %v", fi.Mode())
	}
	// Тот же каталог — тот же корневой и тот же сертификат сервера.
	ca2, err := Load(cfg(dir))
	if err != nil || ca2.Fingerprint() != ca.Fingerprint() {
		t.Fatalf("reload: %v", err)
	}
	srv2, _ := ca2.Server()
	if srv2.Leaf.SerialNumber.Cmp(srv.Leaf.SerialNumber) != 0 {
		t.Error("server cert reissued without a reason")
	}
	if ca2.Renewed {
		t.Error("same names: CA must not be renewed")
	}
	// Адрес вне сетей корневого — новый корневой.
	c5 := cfg(dir)
	c5.Addrs = []netip.Addr{netip.MustParseAddr("10.1.1.1")}
	c5.Networks = []netip.Prefix{netip.MustParsePrefix("10.1.1.0/24")}
	ca5, _ := Load(c5)
	if !ca5.Renewed || ca5.Fingerprint() == ca.Fingerprint() {
		t.Error("CA not renewed for a new network")
	}
	// Сменился адрес — перевыпуск.
	_ = os.Remove(filepath.Join(dir, "ca.key"))
	_ = os.Remove(filepath.Join(dir, "ca.crt"))
	ca, _ = Load(cfg(dir))
	srv, _ = ca.Server()
	c3 := cfg(dir)
	c3.Addrs = []netip.Addr{netip.MustParseAddr("192.168.10.2")}
	ca3, _ := Load(c3)
	srv3, _ := ca3.Server()
	if srv3.Leaf.SerialNumber.Cmp(srv.Leaf.SerialNumber) == 0 {
		t.Error("address change did not reissue")
	}
	// Близко к истечению — перевыпуск.
	c4 := cfg(dir)
	c4.Now = func() time.Time { return time.Now().Add(serverValidity - renewBefore/2) }
	ca4, _ := Load(c4)
	srv4, _ := ca4.Server()
	if srv4.Leaf.SerialNumber.Cmp(srv3.Leaf.SerialNumber) == 0 {
		t.Error("expiring cert not renewed")
	}
}

// Корневой ограничен: им нельзя подписать чужой сайт.
func TestNameConstraints(t *testing.T) {
	ca, err := Load(cfg(""))
	if err != nil {
		t.Fatal(err)
	}
	evil := cfg("")
	evil.Names = []string{"bank.example"}
	evil.Addrs = []netip.Addr{netip.MustParseAddr("203.0.113.5")}
	ca.cfg = evil
	srv, err := ca.Server()
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.CAPEM())
	if _, err := srv.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "bank.example"}); err == nil {
		t.Error("constrained CA signed a foreign name")
	}
	if _, err := srv.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "203.0.113.5"}); err == nil {
		t.Error("constrained CA signed a foreign address")
	}
	b, _ := pem.Decode(ca.CAPEM())
	c, _ := x509.ParseCertificate(b.Bytes)
	if !c.PermittedDNSDomainsCritical || len(c.PermittedIPRanges) != 1 || !c.MaxPathLenZero {
		t.Errorf("constraints %+v %v", c.PermittedDNSDomains, c.PermittedIPRanges)
	}
}
