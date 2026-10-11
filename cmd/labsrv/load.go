package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// load — синтетическая нагрузка домашних сценариев: N потоков загрузки
// (GET /bytes) и M потоков отдачи (POST /sink) на время duration.
//
//	торрент: -down 150 -up 50 -chunk 1000000 -churn   (сотни соединений, обмен в обе стороны)
//	Steam:   -down 8 -chunk 100000000                  (несколько толстых потоков)
//	стрим:   -down 1 -down-mbit 20 -up 1 -up-mbit 8    (ровный просмотр и ровная отдача)
func load(args []string) error {
	fs := flag.NewFlagSet("load", flag.ExitOnError)
	base := fs.String("url", "", "server base URL, e.g. http://203.0.113.10")
	down := fs.Int("down", 0, "download workers")
	up := fs.Int("up", 0, "upload workers")
	chunk := fs.Int64("chunk", 10_000_000, "bytes per request")
	churn := fs.Bool("churn", false, "new TCP connection for every request (many short flows)")
	downMbit := fs.Float64("down-mbit", 0, "pace each download worker to this rate; 0 — unlimited")
	upMbit := fs.Float64("up-mbit", 0, "pace each upload worker to this rate; 0 — unlimited")
	duration := fs.Duration("duration", 60*time.Second, "how long to run")
	_ = fs.Parse(args)
	if *base == "" || *down+*up == 0 || *chunk <= 0 {
		return errors.New("need -url, -down or -up, positive -chunk")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()
	tr := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		DisableKeepAlives:   *churn,
		MaxIdleConnsPerHost: *down + *up,
	}
	c := &http.Client{Transport: tr}
	var rx, tx, reqs, errs atomic.Int64
	var wg sync.WaitGroup
	for range *down {
		wg.Go(func() {
			url := *base + "/bytes?n=" + strconv.FormatInt(*chunk, 10)
			for ctx.Err() == nil {
				req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
				resp, err := c.Do(req)
				if err == nil {
					// Медленное чтение тормозит отправителя через окно TCP — так
					// ограничивается скорость загрузки без участия сервера.
					_, _ = io.Copy(io.Discard, &pacedReader{ctx: ctx, src: resp.Body, left: *chunk, bps: *downMbit * 1e6 / 8, start: time.Now(), count: &rx})
					resp.Body.Close()
					reqs.Add(1)
				} else if ctx.Err() == nil {
					errs.Add(1)
					time.Sleep(100 * time.Millisecond)
				}
			}
		})
	}
	for range *up {
		wg.Go(func() {
			for ctx.Err() == nil {
				body := &pacedReader{ctx: ctx, left: *chunk, bps: *upMbit * 1e6 / 8, start: time.Now(), count: &tx}
				req, _ := http.NewRequestWithContext(ctx, http.MethodPost, *base+"/sink", body)
				req.ContentLength = -1 // без длины: отдачу можно оборвать по окончании прогона
				resp, err := c.Do(req)
				if err == nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					reqs.Add(1)
				} else if ctx.Err() == nil {
					errs.Add(1)
					time.Sleep(100 * time.Millisecond)
				}
			}
		})
	}
	start := time.Now()
	wg.Wait()
	sec := time.Since(start).Seconds()
	fmt.Printf("load %.0f s: down %.1f Mbit/s, up %.1f Mbit/s, requests %d, errors %d\n",
		sec, float64(rx.Load())*8/1e6/sec, float64(tx.Load())*8/1e6/sec, reqs.Load(), errs.Load())
	return nil
}

// pacedReader читает из src (nil — нули) не быстрее bps (0 — без
// ограничения) и заканчивается по left, концу src или ctx.
type pacedReader struct {
	ctx   context.Context
	src   io.Reader
	left  int64
	bps   float64
	start time.Time
	done  int64
	count *atomic.Int64
}

func (r *pacedReader) Read(p []byte) (int, error) {
	if r.left <= 0 || r.ctx.Err() != nil {
		return 0, io.EOF
	}
	n := int64(min(len(p), len(zeros), 16<<10))
	n = min(n, r.left)
	if r.bps > 0 {
		// Ждём, пока «положено» по времени не догонит отправленное.
		ahead := time.Duration(float64(r.done+n)/r.bps*float64(time.Second)) - time.Since(r.start)
		if ahead > 0 {
			select {
			case <-time.After(ahead):
			case <-r.ctx.Done():
				return 0, io.EOF
			}
		}
	}
	if r.src == nil {
		copy(p, zeros[:n])
	} else {
		k, err := r.src.Read(p[:n])
		r.left -= int64(k)
		r.done += int64(k)
		r.count.Add(int64(k))
		return k, err
	}
	r.left -= n
	r.done += n
	r.count.Add(n)
	return int(n), nil
}
