// Команда labsrv — тестовые серверы «интернета» стенда и клиент UDP-пинга.
//
//	labsrv serve -http :80 -udp :9000 [-portal :8080] [-files dir] [-doh IP:443 -dot IP:853 -dns-ca ca.pem -dns-answer IP]
//	    HTTP (/, /generate_204, /success.txt, /bytes?n=, /sink, /files/), UDP-эхо,
//	    имитация страницы авторизации (captive portal) на отдельном порту,
//	    DoH и DoT с самоподписанным сертификатом на IP (корень — в -dns-ca)
//	labsrv udpping -target 203.0.113.10:9000 -rate 30 -n 90
//	labsrv upload -url http://203.0.113.10/sink -n 50000000
//	labsrv load -url http://203.0.113.10 -down 150 -up 50 -chunk 1000000 -churn -duration 60s
//	labsrv dns -ca ca.pem -server 203.0.113.54=hash -server 203.0.113.56=servfail -udp :5353=answer:203.0.113.250
//	    «резолверы» с поведением: answer:IP, hash (свой адрес на имя), servfail,
//	    drop (молчание); «/150ms» — задержка ответа
//	labsrv dnsload -server 192.168.77.1:53 -qps 500 -names miss|hit|sets -suffix googlevideo.com
//	labsrv tlsget -addr 203.0.113.10:443 -sni name.example -path /whoami
//	    HTTPS-запрос по адресу с любым именем в SNI (сертификат не проверяется)
//	labsrv life -duration 8h -devices 192.168.77.10,192.168.77.11 -out life.jsonl
//
// UDP-пинг имитирует игровой трафик: мелкие пакеты с постоянной частотой;
// печатает RTT (мин/сред/макс), джиттер и потери.
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv4"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: labsrv serve|udpping|upload|load|life|dns|dnsload|tlsget [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "udpping":
		err = udpping(os.Args[2:])
	case "upload":
		err = upload(os.Args[2:])
	case "dns":
		err = dnsServers(os.Args[2:])
	case "dnsload":
		err = dnsload(os.Args[2:])
	case "tlsget":
		err = tlsget(os.Args[2:])
	case "life":
		err = life(os.Args[2:])
	case "load":
		err = load(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "labsrv:", err)
		os.Exit(1)
	}
}

const maxBytes = 10 << 30

var zeros = make([]byte, 64<<10)

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	httpAddr := fs.String("http", ":80", "HTTP listen address")
	udpAddr := fs.String("udp", ":9000", "UDP echo listen address")
	portalAddr := fs.String("portal", "", "captive-portal imitation listen address (any path → 200 HTML)")
	dohAddr := fs.String("doh", "", "DoH listen IP:port (needs -dot, -dns-ca, -dns-answer)")
	dotAddr := fs.String("dot", "", "DoT listen IP:port")
	dnsCA := fs.String("dns-ca", "", "where to write the self-signed DoH/DoT certificate (client root)")
	dnsAns := fs.String("dns-answer", "", "IPv4 answer for any A query")
	files := fs.String("files", "", "serve this directory at /files/ (online lists for loader tests)")
	httpsAddr := fs.String("https", "", "also serve the same over TLS here (IP:port; any SNI, self-signed)")
	_ = fs.Parse(args)

	if *dohAddr != "" {
		ans, err := netip.ParseAddr(*dnsAns)
		if err != nil || *dotAddr == "" || *dnsCA == "" {
			return errors.New("-doh needs -dot, -dns-ca and -dns-answer IPv4")
		}
		if err := serveEncryptedDNS(*dohAddr, *dotAddr, *dnsCA, ans); err != nil {
			return err
		}
	}

	if *portalAddr != "" {
		portal := &http.Server{Addr: *portalAddr, ReadHeaderTimeout: 10 * time.Second,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				io.WriteString(w, "<html><body>Please log in to use the network</body></html>\n")
			})}
		go func() { log.Printf("portal: %v", portal.ListenAndServe()) }()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok\n") })
	// Как у настоящих проверок подключения (gstatic, firefox).
	mux.HandleFunc("GET /generate_204", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("GET /success.txt", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "success\n") })
	// /bytes?n=N — отдать N байт (замер загрузки).
	mux.HandleFunc("GET /bytes", func(w http.ResponseWriter, r *http.Request) {
		n, err := strconv.ParseInt(r.URL.Query().Get("n"), 10, 64)
		if err != nil || n < 0 || n > maxBytes {
			http.Error(w, "bad n", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
		for n > 0 {
			chunk := min(n, int64(len(zeros)))
			if _, err := w.Write(zeros[:chunk]); err != nil {
				return
			}
			n -= chunk
		}
	})
	// /whoami — адрес, с которого пришёл запрос: у каждого канала стенда свой
	// (100.64.<номер>.2) — так клиент узнаёт, каким каналом ушло соединение.
	mux.HandleFunc("GET /whoami", func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		fmt.Fprintf(w, "src=%s\n", host)
	})
	if *files != "" {
		mux.Handle("GET /files/", http.StripPrefix("/files/", http.FileServer(http.Dir(*files))))
	}
	// /sink — принять тело запроса (замер отдачи).
	mux.HandleFunc("POST /sink", func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		fmt.Fprintf(w, "%d\n", n)
	})

	conn, err := net.ListenPacket("udp4", *udpAddr)
	if err != nil {
		return err
	}
	// Слушающий все адреса (":9001") сокет иначе ответил бы с адреса
	// интерфейса маршрута, а не с адреса запроса: клиент и NAT такой ответ
	// не примут. Отвечаем с адреса назначения запроса (IP_PKTINFO).
	pc := ipv4.NewPacketConn(conn)
	_ = pc.SetControlMessage(ipv4.FlagDst, true)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, cm, addr, err := pc.ReadFrom(buf)
			if err != nil {
				log.Printf("udp: %v", err)
				return
			}
			var wcm *ipv4.ControlMessage
			if cm != nil && cm.Dst != nil {
				wcm = &ipv4.ControlMessage{Src: cm.Dst}
			}
			reply := buf[:n]
			if bytes.Contains(reply, []byte("whoami")) {
				if ua, ok := addr.(*net.UDPAddr); ok {
					reply = []byte("src=" + ua.IP.String() + "\n")
				}
			}
			_, _ = pc.WriteTo(reply, wcm, addr)
		}
	}()
	if *httpsAddr != "" {
		ap, err := netip.ParseAddrPort(*httpsAddr)
		if err != nil {
			return fmt.Errorf("-https: %w", err)
		}
		cert, _, err := selfSigned(ap.Addr())
		if err != nil {
			return err
		}
		tsrv := &http.Server{Addr: *httpsAddr, Handler: mux, ReadHeaderTimeout: 10 * time.Second,
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}
		go func() { log.Printf("https: %v", tsrv.ListenAndServeTLS("", "")) }()
	}
	log.Printf("serving http %s, udp echo %s", *httpAddr, *udpAddr)
	srv := &http.Server{Addr: *httpAddr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	return srv.ListenAndServe()
}

func udpping(args []string) error {
	fs := flag.NewFlagSet("udpping", flag.ExitOnError)
	target := fs.String("target", "", "host:port of UDP echo")
	rate := fs.Int("rate", 30, "packets per second")
	count := fs.Int("n", 90, "packets to send")
	size := fs.Int("size", 100, "payload size, bytes (>= 16)")
	wait := fs.Duration("wait", time.Second, "wait for late replies after the last packet")
	_ = fs.Parse(args)
	if *target == "" || *rate <= 0 || *count <= 0 || *size < 16 {
		return errors.New("need -target, positive -rate/-n and -size >= 16")
	}
	conn, err := net.Dial("udp", *target)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Отправка и приём — в разных горутинах: время отправки храним атомарно.
	sent := make([]atomic.Int64, *count)
	rtts := make([]time.Duration, 0, *count)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		seen := make([]bool, *count)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(*wait + time.Duration(*count)*time.Second/time.Duration(*rate)))
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			if n < 16 {
				continue
			}
			seq := binary.BigEndian.Uint64(buf[:8])
			if seq >= uint64(*count) || seen[seq] {
				continue
			}
			seen[seq] = true
			rtts = append(rtts, time.Duration(time.Now().UnixNano()-sent[seq].Load()))
			if len(rtts) == *count {
				return
			}
		}
	}()

	payload := make([]byte, *size)
	tick := time.NewTicker(time.Second / time.Duration(*rate))
	for i := range *count {
		<-tick.C
		binary.BigEndian.PutUint64(payload[:8], uint64(i))
		sent[i].Store(time.Now().UnixNano())
		if _, err := conn.Write(payload); err != nil {
			return err
		}
	}
	tick.Stop()
	select {
	case <-done:
	case <-time.After(*wait):
		_ = conn.SetReadDeadline(time.Now())
		<-done
	}
	printStats(*count, rtts)
	return nil
}

// upload — отдача потоком (POST /sink): печатает, сколько отправлено и чем
// закончилось; нужна для проверки, что отдача на умершем канале обрывается.
func upload(args []string) error {
	fs := flag.NewFlagSet("upload", flag.ExitOnError)
	target := fs.String("url", "", "URL of /sink")
	n := fs.Int64("n", 50_000_000, "bytes to send")
	timeout := fs.Duration("timeout", 60*time.Second, "overall timeout")
	_ = fs.Parse(args)
	if *target == "" {
		return errors.New("need -url")
	}
	pr, pw := io.Pipe()
	var sent atomic.Int64 // пишет горутина-источник, читает итоговая печать
	go func() {
		for sent.Load() < *n {
			k := min(int64(len(zeros)), *n-sent.Load())
			if _, err := pw.Write(zeros[:k]); err != nil {
				return
			}
			sent.Add(k)
		}
		pw.Close()
	}()
	start := time.Now()
	c := &http.Client{Timeout: *timeout}
	resp, err := c.Post(*target, "application/octet-stream", pr)
	if err == nil {
		resp.Body.Close()
	}
	fmt.Printf("sent %d of %d in %.1f s: %v\n", sent.Load(), *n, time.Since(start).Seconds(), err)
	return nil
}

func printStats(sent int, rtts []time.Duration) {
	loss := float64(sent-len(rtts)) * 100 / float64(sent)
	if len(rtts) == 0 {
		fmt.Printf("sent %d, received 0, loss 100.0%%\n", sent)
		return
	}
	ms := func(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }
	minR, maxR, sum := rtts[0], rtts[0], time.Duration(0)
	var jitter float64
	for i, r := range rtts {
		minR, maxR, sum = min(minR, r), max(maxR, r), sum+r
		if i > 0 {
			jitter += math.Abs(ms(r) - ms(rtts[i-1]))
		}
	}
	if len(rtts) > 1 {
		jitter /= float64(len(rtts) - 1)
	}
	fmt.Printf("sent %d, received %d, loss %.1f%%, rtt min/avg/max %.2f/%.2f/%.2f ms, jitter %.2f ms\n",
		sent, len(rtts), loss, ms(minR), ms(sum)/float64(len(rtts)), ms(maxR), jitter)
}

// tlsget — HTTPS по адресу с заданным именем в SNI: проверка обхода DPI
// на стенде (имя решает hostlist движка, адрес — множество обхода).
func tlsget(args []string) error {
	fs := flag.NewFlagSet("tlsget", flag.ExitOnError)
	addr := fs.String("addr", "203.0.113.10:443", "server IP:port")
	sni := fs.String("sni", "", "name in ClientHello")
	path := fs.String("path", "/whoami", "request path")
	timeout := fs.Duration("timeout", 5*time.Second, "overall timeout")
	_ = fs.Parse(args)
	start := time.Now()
	d := &net.Dialer{Timeout: *timeout}
	c, err := tls.DialWithDialer(d, "tcp4", *addr, &tls.Config{ServerName: *sni, InsecureSkipVerify: true}) //nolint:gosec // стенд: самоподписанный сервер
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(*timeout))
	if _, err := fmt.Fprintf(c, "GET %s HTTP/1.0\r\nHost: %s\r\n\r\n", *path, *sni); err != nil {
		return err
	}
	body, err := io.ReadAll(io.LimitReader(c, 1<<20))
	if err != nil && len(body) == 0 {
		return err
	}
	_, b, _ := strings.Cut(string(body), "\r\n\r\n")
	fmt.Printf("%s (%d ms)\n", strings.TrimSpace(b), time.Since(start).Milliseconds())
	return nil
}
