package sqm

import (
	"strings"
	"testing"
	"time"

	"tross/core/model"
)

const mbit = 1_000_000

var t0 = time.Date(2026, 10, 15, 20, 0, 0, 0, time.UTC)

func TestTinFor(t *testing.T) {
	for p, want := range map[model.Priority]Tin{
		model.PriorityHigh:   TinVoice,
		model.PriorityVideo:  TinVideo,
		model.PriorityNormal: TinBestEffort,
		model.PriorityLow:    TinBulk,
		"":                   TinBestEffort,
	} {
		if got := TinFor(p); got != want {
			t.Errorf("TinFor(%q) = %s, want %s", p, got, want)
		}
	}
}

func TestParamsValidate(t *testing.T) {
	for _, p := range []Params{WiredParams(), LTEParams()} {
		if err := p.Validate(); err != nil {
			t.Errorf("defaults: %v", err)
		}
	}
	for name, mut := range map[string]func(*Params){
		"start below min": func(p *Params) { p.Start = 0.7 },
		"max over 100":    func(p *Params) { p.Max = 1.1 },
		"zero min":        func(p *Params) { p.Min, p.Start = 0, 0.5 },
		"no delay":        func(p *Params) { p.Delay = 0 },
		"base not grow":   func(p *Params) { p.BaseGrow = 1 },
	} {
		p := WiredParams()
		mut(&p)
		if p.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func link(p Params) *Link { return &Link{Down: NewShaper(p, 0), Up: NewShaper(p, 0)} }

// До базы очередь без ограничения; база появляется по насыщению канала
// (рост задержки при заметном трафике), не по любому всплеску задержки.
func TestPassiveBaseFromSaturation(t *testing.T) {
	l := link(LTEParams())
	if l.Down.Rate() != 0 {
		t.Fatal("no base must mean no rate limit")
	}
	if d, _ := l.Observe(Sample{At: t0, DownBps: 500_000, Delay: 80 * time.Millisecond}); d != "" || l.Down.Rate() != 0 {
		t.Errorf("tiny traffic set a base: %q", d)
	}
	if d, _ := l.Observe(Sample{At: t0, DownBps: 40 * mbit, Delay: 5 * time.Millisecond}); d != "" || l.Down.Rate() != 0 {
		t.Errorf("traffic without delay set a base: %q", d)
	}
	d, u := l.Observe(Sample{At: t0, DownBps: 40 * mbit, UpBps: 300_000, Delay: 80 * time.Millisecond})
	if base, basis := l.Down.Base(); base != 40*mbit || basis != BasisPassive || l.Down.Rate() != 36*mbit || !strings.Contains(d, "passive base") {
		t.Errorf("base %d %s, rate %d, why %q", base, basis, l.Down.Rate(), d)
	}
	if u != "" || l.Up.Rate() != 0 {
		t.Errorf("idle upload got a base: %q", u)
	}
}

func TestManualBaseWinsOverTests(t *testing.T) {
	s := NewShaper(WiredParams(), 100*mbit)
	if s.SetTested(500*mbit) || s.Rate() != 90*mbit {
		t.Errorf("manual base overridden: rate %d", s.Rate())
	}
	s = NewShaper(WiredParams(), 0)
	if !s.SetTested(500*mbit) || s.Rate() != 450*mbit {
		t.Errorf("tested base: rate %d", s.Rate())
	}
}

func TestAutoStepsAndLimits(t *testing.T) {
	l := link(WiredParams())
	l.Down.SetTested(100 * mbit)
	l.Up.SetTested(20 * mbit)
	at := t0
	loadedBloat := func(d time.Duration) string {
		at = at.Add(d)
		down, _ := l.Observe(Sample{At: at, DownBps: l.Down.Rate(), Delay: 40 * time.Millisecond})
		return down
	}
	if loadedBloat(0) == "" || l.Down.Fraction() != 0.88 {
		t.Fatalf("first step down: %.3f", l.Down.Fraction())
	}
	// Не чаще DownEvery.
	if loadedBloat(5*time.Second) != "" || l.Down.Fraction() != 0.88 {
		t.Errorf("stepped again within 5 s: %.3f", l.Down.Fraction())
	}
	for range 20 {
		loadedBloat(10 * time.Second)
	}
	if l.Down.Fraction() != 0.80 {
		t.Errorf("floor: %.3f, want 0.80", l.Down.Fraction())
	}
	// База из теста под пределом не двигается: процент упёрся в 80 %.
	if base, _ := l.Down.Base(); base != 100*mbit {
		t.Errorf("tested base moved to %d", base)
	}
	// Задержку дала отдача (упирается в свою очередь) — загрузку не трогаем.
	at = at.Add(time.Minute)
	down, up := l.Observe(Sample{At: at, DownBps: 10 * mbit, UpBps: l.Up.Rate(), Delay: 40 * time.Millisecond})
	if down != "" || up == "" {
		t.Errorf("blame: down %q, up %q — want upload only", down, up)
	}
	// Загрузка упирается в очередь, задержка ровная — медленный рост до 97 %.
	for range 60 {
		at = at.Add(30 * time.Second)
		l.Observe(Sample{At: at, DownBps: l.Down.Rate(), Delay: 2 * time.Millisecond})
	}
	if l.Down.Fraction() != 0.97 {
		t.Errorf("ceiling: %.3f, want 0.97", l.Down.Fraction())
	}
}

func TestAutoOffKeepsStart(t *testing.T) {
	p := WiredParams()
	p.Auto = false
	l := link(p)
	l.Down.SetTested(100 * mbit)
	if d, _ := l.Observe(Sample{At: t0, DownBps: 90 * mbit, Delay: time.Second}); d != "" || l.Down.Rate() != 90*mbit {
		t.Errorf("auto off adjusted: %q", d)
	}
}

// run — грубая модель канала под полной загрузкой: очередь копится у
// провайдера, когда очередь Tross пропускает больше, чем тянет канал.
func run(l *Link, capacity func(i int) uint64, rounds int) (rates []uint64) {
	at := t0
	for i := range rounds {
		at = at.Add(2 * time.Second)
		c := capacity(i)
		rate := l.Down.Rate()
		bps, delay := min(rate, c), 2*time.Millisecond
		if rate == 0 || rate > c*98/100 {
			bps, delay = c, 60*time.Millisecond
		}
		l.Observe(Sample{At: at, DownBps: bps, UpBps: 200_000, Delay: delay})
		rates = append(rates, l.Down.Rate())
	}
	return rates
}

// Тест скорости завысил базу на 10 % — процент сползает, пока очередь не
// встанет ниже настоящей скорости, и дальше не «качается».
func TestConvergesBelowCapacity(t *testing.T) {
	l := link(WiredParams())
	l.Down.SetTested(550 * mbit) // канал на деле 500
	rates := run(l, func(int) uint64 { return 500 * mbit }, 600)
	last := rates[len(rates)-1]
	if last > 490*mbit || last < 440*mbit {
		t.Errorf("settled at %s, want just below 500 Mbit/s", Mbit(last))
	}
	lo, hi := last, last
	for _, r := range rates[len(rates)-150:] {
		lo, hi = min(lo, r), max(hi, r)
	}
	if hi-lo > 15*mbit {
		t.Errorf("oscillates %s…%s over the last 5 min", Mbit(lo), Mbit(hi))
	}
	t.Logf("settled at %s (%.1f %% of tested base)", Mbit(last), l.Down.Fraction()*100)
}

// LTE: база — по насыщению; скорость сети упала втрое — очередь догоняет
// сразу (прошедший трафик — новая база), выросла — растёт обратно.
func TestLTEFollowsCapacity(t *testing.T) {
	l := link(LTEParams())
	capacity := func(i int) uint64 {
		switch {
		case i < 300:
			return 40 * mbit
		case i < 900:
			return 12 * mbit
		}
		return 40 * mbit
	}
	rates := run(l, capacity, 2400)
	at := func(i int) uint64 { return rates[i] }
	if r := at(299); r == 0 || r > 40*mbit*98/100 {
		t.Errorf("before the drop: %s", Mbit(r))
	}
	if r := at(899); r > 12*mbit*98/100 || r < 6*mbit {
		t.Errorf("after the drop to 12 Mbit/s: %s", Mbit(r))
	}
	if r := at(2399); r < 30*mbit || r > 40*mbit*98/100 {
		t.Errorf("after recovery to 40 Mbit/s: %s", Mbit(r))
	}
	t.Logf("LTE: %s → %s → %s", Mbit(at(299)), Mbit(at(899)), Mbit(at(2399)))
}

func ms(n int) time.Duration { return time.Duration(n) * time.Millisecond }

// Прирост — по каждой цели от её базы (цели на разном расстоянии), медиана.
func TestDelayPerTarget(t *testing.T) {
	var d Delay
	if _, ok := d.Observe(nil, false); ok {
		t.Error("no samples must give no delay")
	}
	d.Observe(map[string]time.Duration{"msk": ms(5), "sto": ms(30), "fra": ms(40)}, false)
	got, _ := d.Observe(map[string]time.Duration{"msk": ms(25), "sto": ms(50), "fra": ms(41)}, true)
	if got != ms(20) {
		t.Errorf("median delta = %v, want 20ms", got)
	}
	// Под нагрузкой база не ползёт: долгая очередь не становится «нормой».
	for range 500 {
		d.Observe(map[string]time.Duration{"msk": ms(25), "sto": ms(50), "fra": ms(60)}, true)
	}
	if got, _ := d.Observe(map[string]time.Duration{"msk": ms(25), "sto": ms(50), "fra": ms(60)}, true); got != ms(20) {
		t.Errorf("after long load delta = %v, want still 20ms", got)
	}
	// В простое — ползёт к новой задержке (маршрут стал длиннее).
	for range 300 {
		d.Observe(map[string]time.Duration{"msk": ms(12), "sto": ms(37), "fra": ms(47)}, false)
	}
	if got, _ := d.Observe(map[string]time.Duration{"msk": ms(12), "sto": ms(37), "fra": ms(47)}, false); got > ms(1) {
		t.Errorf("idle drift: delta %v, want ~0", got)
	}
}

func TestRestoreKeepsRateAcrossRestart(t *testing.T) {
	s := NewShaper(WiredParams(), 0)
	s.Restore(450 * mbit)
	if b, basis := s.Base(); basis != BasisRestored || s.Rate() != 450*mbit || b != 500*mbit {
		t.Errorf("restored: rate %s, base %s %s", Mbit(s.Rate()), Mbit(b), basis)
	}
	m := NewShaper(WiredParams(), 100*mbit)
	if m.Restore(450 * mbit); m.Rate() != 90*mbit {
		t.Errorf("restore overrode manual base: %s", Mbit(m.Rate()))
	}
}

// Без базы задержку, раздутую загрузкой, нельзя приписать отдаче с её
// подтверждениями: база отдачи в пару Мбит/с урезала бы канал.
func TestNoBaseBlamesDominantDirection(t *testing.T) {
	l := link(WiredParams())
	d, u := l.Observe(Sample{At: t0, DownBps: 180 * mbit, UpBps: 4 * mbit, Delay: 300 * time.Millisecond})
	if d == "" || u != "" || l.Up.Rate() != 0 {
		t.Errorf("down %q, up %q, up rate %s — want only download learned", d, u, Mbit(l.Up.Rate()))
	}
	// Отдача сама упирается в канал (торрент раздаёт), загрузка уже с
	// базой и ниже своей очереди — виновата отдача.
	_, u = l.Observe(Sample{At: t0.Add(30 * time.Second), DownBps: 20 * mbit, UpBps: 45 * mbit, Delay: 300 * time.Millisecond})
	if u == "" || l.Up.Rate() == 0 {
		t.Errorf("saturated upload not learned: %q", u)
	}
}
