package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"slices"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// dnsload — нагрузка на DNS дома с постоянной частотой: имена — повтор
// нескольких (из кэша), каждое новое (промах кэша) или каждое новое внутри
// домена профиля (промах + наполнение множеств ядра). Печатает задержку и
// потери.
func dnsload(args []string) error {
	fs := flag.NewFlagSet("dnsload", flag.ExitOnError)
	server := fs.String("server", "192.168.77.1:53", "DNS server")
	qps := fs.Int("qps", 100, "queries per second")
	duration := fs.Duration("duration", 20*time.Second, "how long to send")
	names := fs.String("names", "miss", "hit: 16 repeated names; miss: every name new; sets: every name new under -suffix")
	suffix := fs.String("suffix", "load.example", "name suffix")
	timeout := fs.Duration("timeout", 2*time.Second, "an unanswered query counts as lost after this")
	_ = fs.Parse(args)
	if *qps <= 0 || *qps > 20000 {
		return errors.New("-qps: 1–20000")
	}
	c, err := net.Dial("udp4", *server)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.(*net.UDPConn).SetReadBuffer(4 << 20)

	// ID запроса → время отправки; ID — 16 бит, при 20000 запросов в секунду
	// и 2 с ожидания повтор ID раньше ответа невозможен (40000 < 65536).
	var mu sync.Mutex
	sent := map[uint16]time.Time{}
	var lat []time.Duration
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		for {
			_ = c.SetReadDeadline(time.Now().Add(*timeout + time.Second))
			n, err := c.Read(buf)
			if err != nil {
				return
			}
			if n < 12 {
				continue
			}
			id := binary.BigEndian.Uint16(buf)
			mu.Lock()
			if t, ok := sent[id]; ok {
				lat = append(lat, time.Since(t))
				delete(sent, id)
			}
			mu.Unlock()
		}
	}()

	start := time.Now()
	total := int(duration.Seconds() * float64(*qps))
	var id uint16
	var lost int
	for i := range total {
		// Расписание по времени, а не тикер: при отставании — догоняем.
		if d := time.Until(start.Add(time.Duration(i) * time.Second / time.Duration(*qps))); d > 0 {
			time.Sleep(d)
		}
		var name string
		switch *names {
		case "hit":
			name = fmt.Sprintf("h%d.%s.", i%16, *suffix)
		case "miss", "sets":
			name = fmt.Sprintf("q%d-%d.%s.", start.UnixNano()%1e6, i, *suffix)
		default:
			return fmt.Errorf("-names %q", *names)
		}
		id++
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
		_ = b.StartQuestions()
		_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
		q, _ := b.Finish()
		mu.Lock()
		// Старше тайм-аута — потерян (и освобождает ID).
		for k, t := range sent {
			if time.Since(t) > *timeout {
				delete(sent, k)
				lost++
			}
		}
		sent[id] = time.Now()
		mu.Unlock()
		if _, err := c.Write(q); err != nil {
			return err
		}
	}
	elapsed := time.Since(start)
	time.Sleep(*timeout)
	mu.Lock()
	lost += len(sent)
	got := slices.Clone(lat)
	mu.Unlock()
	_ = c.SetReadDeadline(time.Now())
	<-done
	slices.Sort(got)
	pct := func(p float64) float64 {
		if len(got) == 0 {
			return 0
		}
		return float64(got[min(len(got)-1, int(p*float64(len(got))))]) / float64(time.Millisecond)
	}
	fmt.Printf("names %s qps %d: sent %d in %.1f s (%.0f/s), answered %d, lost %d (%.2f%%), latency p50 %.2f p95 %.2f p99 %.2f max %.2f ms\n",
		*names, *qps, total, elapsed.Seconds(), float64(total)/elapsed.Seconds(), len(got), lost, 100*float64(lost)/float64(max(total, 1)),
		pct(0.5), pct(0.95), pct(0.99), pct(1))
	return nil
}
