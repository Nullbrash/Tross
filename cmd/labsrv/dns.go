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
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// dnsAnswer — ответ «интернета» стенда на любой запрос: A — answer, другие
// типы — пустой NOERROR (как dnsmasq стенда с address=/#/).
func dnsAnswer(query []byte, answer netip.Addr) ([]byte, error) {
	return dnsBehavior{mode: "answer", ip: answer}.reply(query)
}

// dnsBehavior — поведение «резолвера» стенда: answer — один адрес на всё;
// hash — свой адрес на каждое имя (198.51.100.1–254: множества доменов не
// пересекаются, у каждого сайта — свой адрес); servfail; drop — молчание.
type dnsBehavior struct {
	mode  string
	ip    netip.Addr
	delay time.Duration
}

// parseBehavior — «hash», «hash/150ms», «answer:203.0.113.250», «servfail»,
// «drop».
func parseBehavior(s string) (dnsBehavior, error) {
	var b dnsBehavior
	mode, delay, ok := strings.Cut(s, "/")
	if ok {
		d, err := time.ParseDuration(delay)
		if err != nil {
			return b, err
		}
		b.delay = d
	}
	mode, ip, _ := strings.Cut(mode, ":")
	b.mode = mode
	switch mode {
	case "answer":
		a, err := netip.ParseAddr(ip)
		if err != nil || !a.Is4() {
			return b, fmt.Errorf("answer needs IPv4: %q", ip)
		}
		b.ip = a
	case "hash", "servfail", "drop":
	default:
		return b, fmt.Errorf("unknown dns behaviour %q", mode)
	}
	return b, nil
}

// hashAddr — адрес имени для режима hash.
func hashAddr(name string) netip.Addr {
	h := fnv.New32a()
	h.Write([]byte(strings.ToLower(strings.TrimSuffix(name, "."))))
	return netip.AddrFrom4([4]byte{198, 51, 100, byte(1 + h.Sum32()%254)})
}

// reply — ответ по поведению; nil без ошибки — не отвечать (drop).
func (b dnsBehavior) reply(query []byte) ([]byte, error) {
	if b.delay > 0 {
		time.Sleep(b.delay)
	}
	if b.mode == "drop" {
		return nil, nil
	}
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
	rh := dnsmessage.Header{ID: h.ID, Response: true, RecursionDesired: h.RecursionDesired, RecursionAvailable: true}
	if b.mode == "servfail" {
		rh.RCode = dnsmessage.RCodeServerFailure
	}
	bld := dnsmessage.NewBuilder(nil, rh)
	bld.EnableCompression()
	if err := bld.StartQuestions(); err != nil {
		return nil, err
	}
	if err := bld.Question(q); err != nil {
		return nil, err
	}
	if err := bld.StartAnswers(); err != nil {
		return nil, err
	}
	if q.Type == dnsmessage.TypeA && b.mode != "servfail" {
		a := b.ip
		if b.mode == "hash" {
			a = hashAddr(q.Name.String())
		}
		h := dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}
		if err := bld.AResource(h, dnsmessage.AResource{A: a.As4()}); err != nil {
			return nil, err
		}
	}
	return bld.Finish()
}

// selfSigned — сертификат на IP сервера; он же корень для клиента (PEM).
func selfSigned(ip netip.Addr) (tls.Certificate, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
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
		return tls.Certificate{}, nil, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// dnsServers — «резолверы» стенда с разным поведением (labsrv dns): DoH и
// DoT на каждом -server IP=поведение (корни всех — в одном файле -ca) и
// обычный DNS по UDP на -udp адрес=поведение (провайдер, перехватывающий
// DNS).
func dnsServers(args []string) error {
	fs := flag.NewFlagSet("dns", flag.ExitOnError)
	caPath := fs.String("ca", "", "write the roots of all -server certificates here")
	var servers, udps multiFlag
	fs.Var(&servers, "server", "IP=behaviour: DoH on :443 and DoT on :853 (repeatable)")
	fs.Var(&udps, "udp", "addr:port=behaviour: plain DNS over UDP (repeatable)")
	_ = fs.Parse(args)
	if len(servers) > 0 && *caPath == "" {
		return errors.New("-server needs -ca")
	}
	var roots []byte
	for _, s := range servers {
		ip, beh, ok := strings.Cut(s, "=")
		a, err := netip.ParseAddr(ip)
		if !ok || err != nil {
			return fmt.Errorf("-server %q: want IP=behaviour", s)
		}
		b, err := parseBehavior(beh)
		if err != nil {
			return err
		}
		cert, pemCert, err := selfSigned(a)
		if err != nil {
			return err
		}
		roots = append(roots, pemCert...)
		if err := serveDoHDoT(netip.AddrPortFrom(a, 443).String(), netip.AddrPortFrom(a, 853).String(), cert, b); err != nil {
			return err
		}
	}
	if *caPath != "" {
		if err := os.WriteFile(*caPath, roots, 0o644); err != nil {
			return err
		}
	}
	for _, u := range udps {
		addr, beh, ok := strings.Cut(u, "=")
		if !ok {
			return fmt.Errorf("-udp %q: want addr:port=behaviour", u)
		}
		b, err := parseBehavior(beh)
		if err != nil {
			return err
		}
		pc, err := net.ListenPacket("udp4", addr)
		if err != nil {
			return err
		}
		go func() {
			buf := make([]byte, 1500)
			for {
				n, from, err := pc.ReadFrom(buf)
				if err != nil {
					log.Printf("dns udp: %v", err)
					return
				}
				if resp, err := b.reply(buf[:n]); err == nil && resp != nil {
					_, _ = pc.WriteTo(resp, from)
				}
			}
		}()
		log.Printf("serving plain dns %s (%s)", addr, b.mode)
	}
	select {}
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// serveEncryptedDNS — DoH (POST /dns-query, RFC 8484) и DoT на одном IP.
func serveEncryptedDNS(dohAddr, dotAddr, caPath string, answer netip.Addr) error {
	ap, err := netip.ParseAddrPort(dohAddr)
	if err != nil {
		return err
	}
	cert, pemCert, err := selfSigned(ap.Addr())
	if err != nil {
		return err
	}
	if err := os.WriteFile(caPath, pemCert, 0o644); err != nil {
		return err
	}
	return serveDoHDoT(dohAddr, dotAddr, cert, dnsBehavior{mode: "answer", ip: answer})
}

// serveDoHDoT — DoH и DoT с поведением b; отказ слушать — ошибка сразу.
func serveDoHDoT(dohAddr, dotAddr string, cert tls.Certificate, b dnsBehavior) error {
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /dns-query", func(w http.ResponseWriter, r *http.Request) {
		q, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		if err != nil || r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "want application/dns-message", http.StatusUnsupportedMediaType)
			return
		}
		resp, err := b.reply(q)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if resp == nil {
			// Молчание: держать запрос, пока клиент не бросит.
			<-r.Context().Done()
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(resp)
	})
	dl, err := net.Listen("tcp", dohAddr)
	if err != nil {
		return err
	}
	doh := &http.Server{Handler: mux, TLSConfig: cfg, ReadHeaderTimeout: 10 * time.Second}
	go func() { log.Printf("doh: %v", doh.ServeTLS(dl, "", "")) }()

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
			go serveDoT(c, b)
		}
	}()
	log.Printf("serving doh %s, dot %s (%s)", dohAddr, dotAddr, b.mode)
	return nil
}

func serveDoT(c net.Conn, b dnsBehavior) {
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
		resp, err := b.reply(q)
		if err != nil {
			return
		}
		if resp == nil {
			continue
		}
		binary.BigEndian.PutUint16(n[:], uint16(len(resp)))
		if _, err := c.Write(append(n[:], resp...)); err != nil {
			return
		}
	}
}
