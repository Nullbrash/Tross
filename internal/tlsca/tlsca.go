// Package tlsca — свой корневой сертификат Tross и сертификат интерфейса
// для HTTPS в домашней сети. Корневой ограничен (Name Constraints) именами
// и адресами Tross: даже с украденным ключом им не подписать чужой сайт на
// телефоне, где он установлен.
package tlsca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	caValidity     = 10 * 365 * 24 * time.Hour
	serverValidity = 365 * 24 * time.Hour
	// renewBefore — сертификат сервера перевыпускается заранее.
	renewBefore = 30 * 24 * time.Hour
)

// Config — что подписывается.
type Config struct {
	// Dir — где ключи и сертификаты; пусто — только в памяти («сухой»
	// режим без каталога данных).
	Dir string
	// Names — имена интерфейса (tross.lan); Addrs — его адреса.
	Names []string
	Addrs []netip.Addr
	// Networks — сети LAN: корневой подписывает только адреса в них.
	Networks []netip.Prefix
	Now      func() time.Time
}

// CA — корневой сертификат и выпуск сертификата интерфейса.
type CA struct {
	// Renewed — корневой создан заново: прежний не покрывал имена и адреса
	// (его надо заново поставить на телефоны и ПК).
	Renewed bool
	cfg     Config
	key     *ecdsa.PrivateKey
	cert    *x509.Certificate
	caPEM   []byte
	mu      sync.Mutex
	server  *tls.Certificate
	leaf    *x509.Certificate
}

func (c Config) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

// Load — корневой из каталога или новый; сертификат сервера — по Server.
func Load(cfg Config) (*CA, error) {
	if len(cfg.Names) == 0 && len(cfg.Addrs) == 0 {
		return nil, errors.New("tlsca: no names or addresses")
	}
	c := &CA{cfg: cfg}
	if cfg.Dir != "" {
		if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
			return nil, err
		}
		err := c.loadCA()
		switch {
		case err == nil && c.permits():
			return c, nil
		case err == nil:
			c.Renewed = true
		case !errors.Is(err, os.ErrNotExist):
			return nil, err
		}
	}
	if err := c.newCA(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *CA) loadCA() error {
	kb, err := os.ReadFile(filepath.Join(c.cfg.Dir, "ca.key"))
	if err != nil {
		return err
	}
	cb, err := os.ReadFile(filepath.Join(c.cfg.Dir, "ca.crt"))
	if err != nil {
		return err
	}
	kp, _ := pem.Decode(kb)
	cp, _ := pem.Decode(cb)
	if kp == nil || cp == nil {
		return errors.New("tlsca: bad PEM in the CA files")
	}
	key, err := x509.ParseECPrivateKey(kp.Bytes)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(cp.Bytes)
	if err != nil {
		return err
	}
	c.key, c.cert, c.caPEM = key, cert, cb
	return nil
}

func (c *CA) newCA() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	sn, err := serial()
	if err != nil {
		return err
	}
	now := c.cfg.now()
	tmpl := &x509.Certificate{
		SerialNumber:                sn,
		Subject:                     pkix.Name{CommonName: "Tross home CA", Organization: []string{"Tross"}},
		NotBefore:                   now.Add(-time.Hour),
		NotAfter:                    now.Add(caValidity),
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		MaxPathLenZero:              true,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         c.cfg.Names,
	}
	for _, p := range c.cfg.Networks {
		n := &net.IPNet{IP: p.Masked().Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
		tmpl.PermittedIPRanges = append(tmpl.PermittedIPRanges, n)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	c.key, c.cert = key, cert
	c.caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if c.cfg.Dir != "" {
		if err := writeFile(filepath.Join(c.cfg.Dir, "ca.key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
			return err
		}
		if err := writeFile(filepath.Join(c.cfg.Dir, "ca.crt"), c.caPEM, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func writeFile(path string, b []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// permits — ограничения корневого допускают нынешние имена и адреса.
func (c *CA) permits() bool {
	for _, n := range c.cfg.Names {
		if !slices.Contains(c.cert.PermittedDNSDomains, n) {
			return false
		}
	}
	for _, a := range c.cfg.Addrs {
		if !slices.ContainsFunc(c.cert.PermittedIPRanges, func(r *net.IPNet) bool { return r.Contains(a.AsSlice()) }) {
			return false
		}
	}
	return true
}

// CAPEM — корневой сертификат для установки на телефон и ПК.
func (c *CA) CAPEM() []byte { return bytes.Clone(c.caPEM) }

// Fingerprint — SHA-256 корневого (сверить на телефоне при установке).
func (c *CA) Fingerprint() string {
	sum := sha256Sum(c.cert.Raw)
	parts := make([]string, len(sum))
	for i, x := range sum {
		parts[i] = fmt.Sprintf("%02X", x)
	}
	return strings.Join(parts, ":")
}

// covers — сертификат выписан на эти имена и адреса и не скоро истекает.
func (c *CA) covers(leaf *x509.Certificate) bool {
	if leaf == nil || c.cfg.now().Add(renewBefore).After(leaf.NotAfter) {
		return false
	}
	if !slices.Equal(leaf.DNSNames, c.cfg.Names) || len(leaf.IPAddresses) != len(c.cfg.Addrs) {
		return false
	}
	for i, a := range c.cfg.Addrs {
		if ip, ok := netip.AddrFromSlice(leaf.IPAddresses[i]); !ok || ip.Unmap() != a {
			return false
		}
	}
	return leaf.CheckSignatureFrom(c.cert) == nil
}

// Server — сертификат интерфейса: из каталога, если годится, иначе новый.
func (c *CA) Server() (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.server != nil && c.covers(c.leaf) {
		return c.server, nil
	}
	if c.cfg.Dir != "" {
		if cert, err := tls.LoadX509KeyPair(filepath.Join(c.cfg.Dir, "server.crt"), filepath.Join(c.cfg.Dir, "server.key")); err == nil {
			if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil && c.covers(leaf) {
				cert.Leaf = leaf
				c.server, c.leaf = &cert, leaf
				return c.server, nil
			}
		}
	}
	return c.issueLocked()
}

func (c *CA) issueLocked() (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	now := c.cfg.now()
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: "Tross"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(serverValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     c.cfg.Names,
	}
	for _, a := range c.cfg.Addrs {
		tmpl.IPAddresses = append(tmpl.IPAddresses, a.AsSlice())
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	cert.Leaf = leaf
	if c.cfg.Dir != "" {
		if err := writeFile(filepath.Join(c.cfg.Dir, "server.key"), keyPEM, 0o600); err != nil {
			return nil, err
		}
		if err := writeFile(filepath.Join(c.cfg.Dir, "server.crt"), certPEM, 0o644); err != nil {
			return nil, err
		}
	}
	c.server, c.leaf = &cert, leaf
	return c.server, nil
}

// TLSConfig — для HTTPS-сервера интерфейса; сертификат перевыпускается сам.
func (c *CA) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return c.Server()
		},
	}
}

func sha256Sum(b []byte) [32]byte { return sha256.Sum256(b) }
