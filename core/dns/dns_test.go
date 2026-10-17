package dns

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"tross/core/model"
)

var t0 = time.Date(2026, 10, 16, 21, 0, 0, 0, time.UTC)

const isp1 model.LinkID = "isp1"

func testUpstreams() []Upstream {
	both := []Pool{PoolProtected, PoolFast}
	return []Upstream{
		{Name: "quad9", Pools: both, Backup: "quad9-unfiltered"},
		{Name: "mullvad", Pools: []Pool{PoolProtected}, Backup: "dnssb"},
		{Name: "digitale", Pools: []Pool{PoolProtected}, Backup: "dnssb"},
		{Name: "dns4eu", Pools: []Pool{PoolProtected}, Backup: "dnssb"},
		{Name: "quad9-unfiltered"}, {Name: "dnssb"},
		{Name: "cloudflare", Pools: []Pool{PoolFast}}, {Name: "google", Pools: []Pool{PoolFast}},
	}
}

func testPolicy(t *testing.T) (*Policy, *Health) {
	t.Helper()
	h := NewHealth(DefaultHealthParams())
	p, err := NewPolicy(testUpstreams(), []string{"telegram.org", "youtube.com"}, h, DefaultParams())
	if err != nil {
		t.Fatal(err)
	}
	return p, h
}

// Особо личное — к одному серверу защищённого набора, одинаково для всех
// имён сайта; разные сайты расходятся по серверам; остальное — гонка быстрых.
func TestPlanPools(t *testing.T) {
	p, _ := testPolicy(t)
	a := p.Plan("web.telegram.org", isp1, t0)
	b := p.Plan("core.telegram.org", isp1, t0)
	if a.Race || a.Pool != PoolProtected || a.Upstreams[0] != b.Upstreams[0] {
		t.Errorf("sensitive: %+v vs %+v — want pinned, same server for one site", a, b)
	}
	for _, n := range a.Upstreams {
		if n == "cloudflare" || n == "google" {
			t.Errorf("sensitive plan leaks to fast pool: %v", a.Upstreams)
		}
	}
	if !slices.Contains([]string{"quad9", "mullvad", "digitale", "dns4eu"}, a.Upstreams[0]) {
		t.Errorf("primary %q is not a protected member", a.Upstreams[0])
	}
	f := p.Plan("example.com", isp1, t0)
	if !f.Race || f.Pool != PoolFast || len(f.Upstreams) != 2 {
		t.Errorf("fast: %+v — want race of 2", f)
	}
	// Доли: на сотне сайтов каждый основной защищённый сервер получает свою.
	share := map[string]int{}
	for i := range 400 {
		seq, _ := p.pinned(fmt.Sprintf("site%d.com", i), isp1, t0)
		share[seq[0]]++
	}
	for _, n := range []string{"quad9", "mullvad", "digitale", "dns4eu"} {
		if share[n] < 60 {
			t.Errorf("uneven shares: %v", share)
			break
		}
	}
}

// Отказ основного — доля уходит его назначенному запасному, а не всем.
func TestPinnedBackup(t *testing.T) {
	p, h := testPolicy(t)
	var domain string
	for i := range 100 {
		d := fmt.Sprintf("bank%d.ru", i)
		if seq, _ := p.pinned(d, isp1, t0); seq[0] == "quad9" {
			domain = d
			break
		}
	}
	for range 3 {
		h.Begin("quad9", isp1)
		h.Done("quad9", isp1, t0, 0, false)
	}
	got, _ := p.pinned(domain, isp1, t0.Add(time.Second))
	if got[0] != "quad9-unfiltered" {
		t.Errorf("after quad9 failed: %v — want its backup first", got)
	}
	// Через другой канал quad9 исправен.
	if got, _ := p.pinned(domain, "isp2", t0.Add(time.Second)); got[0] != "quad9" {
		t.Errorf("health must be per link: %v", got)
	}
	// Отложен на 30 с, потом снова пробуется.
	if got, _ := p.pinned(domain, isp1, t0.Add(31*time.Second)); got[0] != "quad9" {
		t.Errorf("after backoff: %v", got)
	}
}

func TestRacePicksHealthy(t *testing.T) {
	p, h := testPolicy(t)
	done := func(up string, rtt time.Duration, ok bool) {
		h.Begin(up, isp1)
		h.Done(up, isp1, t0, rtt, ok)
	}
	done("cloudflare", 15*time.Millisecond, true)
	done("google", 60*time.Millisecond, true)
	done("quad9", 35*time.Millisecond, true)
	if got := p.Plan("example.com", isp1, t0).Upstreams; !slices.Equal(got, []string{"cloudflare", "quad9"}) {
		t.Errorf("race %v — want the two fastest", got)
	}
	for range 3 {
		done("cloudflare", 0, false)
	}
	if got := p.Plan("example.com", isp1, t0.Add(time.Second)).Upstreams; slices.Contains(got, "cloudflare") {
		t.Errorf("race %v — failed server must be skipped", got)
	}
}

func TestPolicyErrors(t *testing.T) {
	h := NewHealth(DefaultHealthParams())
	for name, ups := range map[string][]Upstream{
		"unknown backup": {{Name: "a", Pools: []Pool{PoolProtected, PoolFast}, Backup: "zz"}},
		"no fast":        {{Name: "a", Pools: []Pool{PoolProtected}}},
		"duplicate":      {{Name: "a", Pools: []Pool{PoolProtected, PoolFast}}, {Name: "a"}},
		"bad pool":       {{Name: "a", Pools: []Pool{PoolProtected, PoolFast, "slow"}}},
	} {
		if _, err := NewPolicy(ups, nil, h, DefaultParams()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestHealthBackoffAndPending(t *testing.T) {
	h := NewHealth(DefaultHealthParams())
	fail := func(at time.Time) {
		for range 3 {
			h.Begin("x", isp1)
			h.Done("x", isp1, at, 0, false)
		}
	}
	fail(t0)
	if h.Usable("x", isp1, t0.Add(29*time.Second), 0) || !h.Usable("x", isp1, t0.Add(31*time.Second), 0) {
		t.Error("first backoff must be 30 s")
	}
	fail(t0.Add(31 * time.Second))
	if h.Usable("x", isp1, t0.Add(31*time.Second+59*time.Second), 0) {
		t.Error("second backoff must double")
	}
	h.Begin("x", isp1)
	h.Done("x", isp1, t0.Add(5*time.Minute), 20*time.Millisecond, true)
	if !h.Usable("x", isp1, t0.Add(5*time.Minute), 0) || h.Score("x", isp1) != 20*time.Millisecond {
		t.Error("success must clear backoff and set rtt")
	}
	for range 3 {
		h.Begin("x", isp1)
	}
	if h.Usable("x", isp1, t0.Add(5*time.Minute), 3) {
		t.Error("server with 3 pending must be skipped at limit 3")
	}
}

func TestRace(t *testing.T) {
	r := NewRace(3)
	if r.Offer(Answer{Upstream: "a", Empty: true}) {
		t.Fatal("empty answer must not decide while others may answer")
	}
	if !r.Offer(Answer{Upstream: "b"}) {
		t.Fatal("non-empty answer must decide")
	}
	if w, _ := r.Winner(); w.Upstream != "b" {
		t.Errorf("winner %q, want b (non-empty beats earlier empty)", w.Upstream)
	}
	r = NewRace(2)
	r.Offer(Answer{Upstream: "a", Err: errors.New("timeout")})
	r.Offer(Answer{Upstream: "b", Empty: true})
	if w, _ := r.Winner(); w.Upstream != "b" {
		t.Errorf("winner %q, want b (empty beats error)", w.Upstream)
	}
	r = NewRace(3)
	r.Offer(Answer{Upstream: "a", Err: errors.New("x")})
	r.Settle()
	if w, ok := r.Winner(); !ok || w.Err == nil {
		t.Error("all failed: winner must carry the error")
	}
	if _, ok := NewRace(2).Winner(); ok {
		t.Error("no answers: no winner")
	}
}

func TestCache(t *testing.T) {
	c := NewCache(DefaultCacheParams(2))
	k := Key{Name: "example.com", Type: 1}
	e := Entry{Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, TTL: 100 * time.Second, Stored: t0}
	if c.Get(k, t0).State != Miss {
		t.Fatal("empty cache hit")
	}
	c.Put(k, e)
	if h := c.Get(k, t0.Add(10*time.Second)); h.State != Fresh || h.Left != 90*time.Second || h.Refresh {
		t.Errorf("fresh: %+v", h)
	}
	c.Get(k, t0.Add(20*time.Second))
	// Третье обращение у самого конца срока — популярное имя, обновить заранее, один раз.
	if h := c.Get(k, t0.Add(95*time.Second)); !h.Refresh {
		t.Error("popular name near expiry must be prefetched")
	}
	if h := c.Get(k, t0.Add(96*time.Second)); h.Refresh {
		t.Error("prefetch must be handed out once")
	}
	c.Abort(k)
	// Срок вышел — устаревший ответ отдаётся и обновляется.
	if h := c.Get(k, t0.Add(10*time.Minute)); h.State != Stale || !h.Refresh {
		t.Errorf("stale: %+v", h)
	}
	if h := c.Get(k, t0.Add(2*time.Hour)); h.State != Miss {
		t.Errorf("past stale window: %+v", h)
	}
	// LRU: третья запись вытесняет самую давнюю.
	c.Put(Key{Name: "a", Type: 1}, e)
	c.Put(Key{Name: "b", Type: 1}, e)
	c.Get(Key{Name: "a", Type: 1}, t0)
	c.Put(Key{Name: "c", Type: 1}, e)
	if c.Get(Key{Name: "b", Type: 1}, t0).State != Miss || c.Get(Key{Name: "a", Type: 1}, t0).State != Fresh || c.Len() != 2 {
		t.Error("LRU eviction")
	}
}

func TestDecide(t *testing.T) {
	ix := NewSetIndex([]SetSpec{
		{Name: "tross_dp_youtube_video_0", Domains: []string{"youtube.com", "googlevideo.com"}},
		{Name: "tross_du0", Domains: []string{"youtube.com"}},
	})
	classSet := func(l model.RuleLayer, c model.TrafficClass) string {
		if l == model.LayerOnline {
			return "tross_la_" + string(c)
		}
		return ""
	}
	rules := []model.DomainRule{
		{Pattern: "youtube.com", Match: model.MatchSuffix, Layer: model.LayerManual, Purpose: model.PurposeBypass},
		{Pattern: "youtube.com", Match: model.MatchSuffix, Layer: model.LayerOnline, Purpose: model.PurposeClass, Class: model.ClassStreaming},
		{Pattern: "youtube.com", Match: model.MatchSuffix, Layer: model.LayerOnline, Purpose: model.PurposeInside},
	}
	got := Decide("www.youtube.com", 30*time.Second, ix, rules, classSet, 5*time.Minute, 12*time.Hour)
	want := []string{"tross_dp_youtube_video_0", "tross_du0", "tross_la_streaming"}
	if !slices.Equal(got.Sets, want) || !got.Bypass || got.Never || !got.Inside || got.Timeout != 5*time.Minute {
		t.Errorf("got %+v", got)
	}
	never := []model.DomainRule{
		{Pattern: "ntp.org", Layer: model.LayerBuiltin, Purpose: model.PurposeNever},
		{Pattern: "ntp.org", Layer: model.LayerOnline, Purpose: model.PurposeBypass},
	}
	if got := Decide("pool.ntp.org", time.Hour, ix, never, classSet, 5*time.Minute, 12*time.Hour); got.Bypass || !got.Never || len(got.Sets) != 0 || got.Timeout != time.Hour {
		t.Errorf("never: %+v", got)
	}
	if SetTimeout(48*time.Hour, 5*time.Minute, 12*time.Hour) != 12*time.Hour {
		t.Error("timeout above max")
	}
}

// Весь защищённый набор с запасными отложен: по умолчанию особо личное ждёт
// защищённый (имена не уходят); с SensitiveFallback — временно идёт быстрым.
func TestSensitiveFallback(t *testing.T) {
	p, h := testPolicy(t)
	for _, n := range []string{"quad9", "mullvad", "digitale", "dns4eu", "quad9-unfiltered", "dnssb"} {
		for range 3 {
			h.Begin(n, isp1)
			h.Done(n, isp1, t0, 0, false)
		}
	}
	at := t0.Add(time.Second)
	if got := p.Plan("web.telegram.org", isp1, at); got.Fallback || got.Pool != PoolProtected || slices.Contains(got.Upstreams, "cloudflare") {
		t.Errorf("default (fallback off): %+v — want protected only", got)
	}
	on := DefaultParams()
	on.SensitiveFallback = true
	pf, err := NewPolicy(testUpstreams(), []string{"telegram.org"}, h, on)
	if err != nil {
		t.Fatal(err)
	}
	got := pf.Plan("web.telegram.org", isp1, at)
	if !got.Fallback || !got.Race || got.Pool != PoolFast || slices.Contains(got.Upstreams, "mullvad") {
		t.Errorf("fallback on: %+v — want the fast race", got)
	}
	if got := pf.Plan("web.telegram.org", "isp2", at); got.Fallback {
		t.Errorf("other link is healthy, no fallback: %+v", got)
	}
}

// Участники, различающиеся последним символом, делят ключи поровну (у
// голого FNV один выигрывал почти всегда).
func TestScoreSpreadsSimilarNames(t *testing.T) {
	wins := map[string]int{}
	for i := range 1000 {
		key := fmt.Sprintf("site%d.com", i)
		if Score(key, "isp1") > Score(key, "isp2") {
			wins["isp1"]++
		} else {
			wins["isp2"]++
		}
	}
	if wins["isp1"] < 400 || wins["isp2"] < 400 {
		t.Errorf("uneven: %v", wins)
	}
}
