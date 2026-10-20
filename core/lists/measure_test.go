package lists

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"tross/core/model"
)

// TestMeasureBigLists — память и скорость на настоящих больших списках.
// Только по запросу: TROSS_LISTS_DIR — каталог с файлами src1 (itdog, text),
// src2 (geosite runetfreedom), src4 (re:filter, text).
func TestMeasureBigLists(t *testing.T) {
	dir := os.Getenv("TROSS_LISTS_DIR")
	if dir == "" {
		t.Skip("TROSS_LISTS_DIR not set")
	}
	heap := func() uint64 {
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return m.HeapAlloc
	}
	r := NewRules()
	before := heap()
	load := func(id, file string, parse func([]byte) (Parsed, error)) {
		data, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatal(err)
		}
		t0 := time.Now()
		p, err := parse(data)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if err := r.SetOnline(id, model.DomainRule{Purpose: model.PurposeBypass}, p.Entries); err != nil {
			t.Logf("%s: some rules rejected: %v", id, err)
		}
		t.Logf("%s: %d rules (skipped %d, bad %d) from %d bytes in %v", id, len(p.Entries), p.Skipped, p.Bad, len(data), time.Since(t0).Round(time.Millisecond))
	}
	text := func(b []byte) (Parsed, error) { return ParseText(bytes.NewReader(b)) }
	load("itdog", "src1", text)
	load("refilter", "src4", text)
	afterText := heap()
	for _, cat := range []string{"ru-available-only-inside", "ru-blocked", "ru-blocked-all"} {
		load("rf-"+cat, "src2", func(b []byte) (Parsed, error) { return ParseGeosite(b, []string{cat}) })
	}
	after := heap()
	t.Logf("heap: text lists +%.1f MB, all +%.1f MB", float64(afterText-before)/1e6, float64(after-before)/1e6)
	names := []string{"www.youtube.com", "rutracker.org", "nonexistent-host-12345.example", "a.b.c.d.instagram.com", "mail.ru"}
	const n = 200_000
	t0 := time.Now()
	hits := 0
	for i := range n {
		if _, ok := r.Lookup(names[i%len(names)]); ok {
			hits++
		}
	}
	per := time.Since(t0) / n
	t.Logf("lookup: %v per name (%d of %d matched)", per, hits, n)
	if out := os.Getenv("LAB_MEASURE_OUT"); out != "" {
		_ = os.WriteFile(filepath.Join(out, "lists.txt"), fmt.Appendf(nil, "heap_text_mb %.1f\nheap_all_mb %.1f\nlookup_ns %d\n", float64(afterText-before)/1e6, float64(after-before)/1e6, per.Nanoseconds()), 0o644)
	}
}
