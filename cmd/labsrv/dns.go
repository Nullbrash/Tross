package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// dnsAnswer — ответ «интернета» стенда на любой запрос: A — answer, другие
// типы — пустой NOERROR (как dnsmasq стенда с address=/#/).
func dnsAnswer(query []byte, answer netip.Addr) ([]byte, error) {
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil {
		return nil, err
	}
	qs, err := p.AllQuestions()
	if err != nil || len(qs) != 1 {
		return nil, errors.New("want exactly one question")
	}
	q := qs[0]
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionDesired: h.RecursionDesired, RecursionAvailable: true})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(q); err != nil {
		return nil, err
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	if q.Type == dnsmessage.TypeA {
		rh := dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}
		if err := b.AResource(rh, dnsmessage.AResource{A: answer.As4()}); err != nil {
			return nil, err
		}
	}
	return b.Finish()
}

// selfSigned — сертификат на IP сервера; он же корень для клиента (файл caPath).
func selfSigned(ip netip.Addr, caPath string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "tross lab dns " + ip.String()},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{ip.AsSlice()},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// serveEncryptedDNS — DoH (POST /dns-query, RFC 8484) и DoT на одном IP.
func serveEncryptedDNS(dohAddr, dotAddr, caPath string, answer netip.Addr) error {
	ap, err := netip.ParseAddrPort(dohAddr)
	if err != nil {
		return err
	}
	cert, err := selfSigned(ap.Addr(), caPath)
	if err != nil {
		return err
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /dns-query", func(w http.ResponseWriter, r *http.Request) {
		q, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		if err != nil || r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "want application/dns-message", http.StatusUnsupportedMediaType)
			return
		}
		resp, err := dnsAnswer(q, answer)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(resp)
	})
	doh := &http.Server{Addr: dohAddr, Handler: mux, TLSConfig: cfg, ReadHeaderTimeout: 10 * time.Second}
	go func() { log.Printf("doh: %v", doh.ListenAndServeTLS("", "")) }()

	ln, err := tls.Listen("tcp", dotAddr, cfg)
	if err != nil {
		return err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				log.Printf("dot: %v", err)
				return
			}
			go serveDoT(c, answer)
		}
	}()
	log.Printf("serving doh %s, dot %s, ca %s", dohAddr, dotAddr, caPath)
	return nil
}

func serveDoT(c net.Conn, answer netip.Addr) {
	defer c.Close()
	for {
		_ = c.SetDeadline(time.Now().Add(30 * time.Second))
		var n [2]byte
		if _, err := io.ReadFull(c, n[:]); err != nil {
			return
		}
		q := make([]byte, binary.BigEndian.Uint16(n[:]))
		if _, err := io.ReadFull(c, q); err != nil {
			return
		}
		resp, err := dnsAnswer(q, answer)
		if err != nil {
			return
		}
		binary.BigEndian.PutUint16(n[:], uint16(len(resp)))
		if _, err := c.Write(append(n[:], resp...)); err != nil {
			return
		}
	}
}
