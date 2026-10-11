// Команда labsrv — тестовые серверы «интернета» стенда и клиент UDP-пинга.
//
//	labsrv serve -http :80 -udp :9000 [-portal :8080]
//	    HTTP (/, /generate_204, /success.txt, /bytes?n=, /sink), UDP-эхо,
//	    имитация страницы авторизации (captive portal) на отдельном порту
//	labsrv udpping -target 203.0.113.10:9000 -rate 30 -n 90
//
// UDP-пинг имитирует игровой трафик: мелкие пакеты с постоянной частотой;
// печатает RTT (мин/сред/макс), джиттер и потери.
package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: labsrv serve|udpping [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "udpping":
		err = udpping(os.Args[2:])
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
	_ = fs.Parse(args)

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
	// /sink — принять тело запроса (замер отдачи).
	mux.HandleFunc("POST /sink", func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		fmt.Fprintf(w, "%d\n", n)
	})

	pc, err := net.ListenPacket("udp", *udpAddr)
	if err != nil {
		return err
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				log.Printf("udp: %v", err)
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
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
