package main

import (
	"bytes"
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"
)

func TestPacedReaderRateAndLimit(t *testing.T) {
	var count atomic.Int64
	// 200 КБ на 8 Мбит/с (1 МБ/с) — не быстрее ~0,2 с.
	r := &pacedReader{ctx: context.Background(), left: 200_000, bps: 1_000_000, start: time.Now(), count: &count}
	began := time.Now()
	n, err := io.Copy(io.Discard, r)
	took := time.Since(began)
	if err != nil || n != 200_000 || count.Load() != 200_000 {
		t.Fatalf("copied %d (counted %d), err %v; want exactly the limit", n, count.Load(), err)
	}
	if took < 150*time.Millisecond || took > time.Second {
		t.Fatalf("200 KB at 1 MB/s took %v, want ≈ 0.2 s", took)
	}
}

func TestPacedReaderSourceEndsFirst(t *testing.T) {
	var count atomic.Int64
	src := bytes.NewReader(make([]byte, 50_000))
	r := &pacedReader{ctx: context.Background(), src: src, left: 100_000, start: time.Now(), count: &count}
	n, err := io.Copy(io.Discard, r)
	if err != nil || n != 50_000 || count.Load() != 50_000 {
		t.Fatalf("copied %d (counted %d), err %v; want the source size", n, count.Load(), err)
	}
}

func TestPacedReaderStopsOnCancel(t *testing.T) {
	var count atomic.Int64
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := &pacedReader{ctx: ctx, left: 1 << 30, bps: 1000, start: time.Now(), count: &count}
	if n, _ := io.Copy(io.Discard, r); n != 0 {
		t.Fatalf("cancelled reader produced %d bytes", n)
	}
}
