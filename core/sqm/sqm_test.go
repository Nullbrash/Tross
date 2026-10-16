package sqm

import (
	"slices"
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

// held — одна и та же задержка n раундов подряд (раунд 2 с); причины —
// последние непустые.
func held(l *Link, x Sample, n int) (down, up string) {
	for range n {
		d, u := l.Observe(x)
		if d != "" {
			down = d
		}
		if u != "" {
			up = u
		}
		x.At = x.At.Add(2 * time.Second)
	}
	return down, up
}

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
	d, u := held(l, Sample{At: t0, DownBps: 40 * mbit, UpBps: 300_000, Delay: 80 * time.Millisecond}, confirmRounds)
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
	// Сразу ниже прошедшего: 0,9 × 90 = 81 Мбит/с.
	if loadedBloat(0) == "" || l.Down.Fraction() != 0.81 {
		t.Fatalf("first step down: %.3f", l.Down.Fraction())
	}
	// Не чаще DownEvery.
	if loadedBloat(2*time.Second) != "" || l.Down.Fraction() != 0.81 {
		t.Errorf("stepped again within 5 s: %.3f", l.Down.Fraction())
	}
	for range 20 {
		loadedBloat(10 * time.Second)
	}
	if l.Down.Fraction() != 0.80 {
		t.Errorf("floor: %.3f, want 0.80", l.Down.Fraction())
	}
	// Задержка держится и на 80 %: база из теста — оценка, она снижается
	// (база из конфига — нет, см. TestManualBaseStaysAtFloor).
	if base, _ := l.Down.Base(); base >= 100*mbit {
		t.Errorf("tested base did not shrink under persistent bloat: %d", base)
	}
	// Задержку дала отдача (упирается в свою очередь) — загрузку не трогаем.
	at = at.Add(time.Minute)
	down, up := l.Observe(Sample{At: at, DownBps: l.Down.Rate() / 10, UpBps: l.Up.Rate(), Delay: 40 * time.Millisecond})
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

// Тест скорости завысил базу на 10 % — очередь опускается ниже канала и
// дальше ходит «пилой» под ним (как cake-autorate): важно, что в среднем
// канал используется почти целиком, а задержка — редкие короткие моменты.
func TestConvergesBelowCapacity(t *testing.T) {
	l := link(WiredParams())
	l.Down.SetTested(550 * mbit) // канал на деле 500
	rates := run(l, func(int) uint64 { return 500 * mbit }, 600)
	tail := rates[len(rates)-150:] // последние 5 минут
	var sum, over uint64
	for _, r := range tail {
		sum += r
		if r > 500*mbit*98/100 {
			over++
		}
	}
	mean := sum / uint64(len(tail))
	if mean < 440*mbit {
		t.Errorf("mean queue %s over 5 min — want ≥ 88 %% of the 500 Mbit/s link", Mbit(mean))
	}
	if over*10 > uint64(len(tail)) {
		t.Errorf("queue above the link %d of %d rounds — want ≤ 10 %%", over, len(tail))
	}
	t.Logf("5 min: mean %s, above the link %d of %d rounds", Mbit(mean), over, len(tail))
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
	d, u := held(l, Sample{At: t0, DownBps: 180 * mbit, UpBps: 4 * mbit, Delay: 300 * time.Millisecond}, confirmRounds)
	if d == "" || u != "" || l.Up.Rate() != 0 {
		t.Errorf("down %q, up %q, up rate %s — want only download learned", d, u, Mbit(l.Up.Rate()))
	}
	// Отдача сама упирается в канал (торрент раздаёт), загрузка уже с
	// базой и ниже своей очереди — виновата отдача.
	_, u = held(l, Sample{At: t0.Add(30 * time.Second), DownBps: 20 * mbit, UpBps: 45 * mbit, Delay: 300 * time.Millisecond}, confirmRounds)
	if u == "" || l.Up.Rate() == 0 {
		t.Errorf("saturated upload not learned: %q", u)
	}
}

func TestManualBaseStaysAtFloor(t *testing.T) {
	p := WiredParams()
	l := &Link{Down: NewShaper(p, 100*mbit), Up: NewShaper(p, 0)}
	at := t0
	for range 30 {
		at = at.Add(10 * time.Second)
		l.Observe(Sample{At: at, DownBps: l.Down.Rate(), Delay: 40 * time.Millisecond})
	}
	if base, _ := l.Down.Base(); base != 100*mbit || l.Down.Rate() != 80*mbit {
		t.Errorf("manual base %s, rate %s — want 100 and the 80 %% floor", Mbit(base), Mbit(l.Down.Rate()))
	}
}

// Сервер теста медленнее канала (300 при настоящих 500): тест — нижняя
// граница, база растёт по реальному трафику; следующий такой же тест её не
// опускает обратно.
func TestSlowTestServerDoesNotCapLink(t *testing.T) {
	l := link(WiredParams())
	l.Down.SetTested(300 * mbit)
	rates := run(l, func(int) uint64 { return 500 * mbit }, 3000)
	grown := rates[len(rates)-1]
	if grown < 440*mbit || grown > 490*mbit {
		t.Errorf("after 100 min of full load: %s, want just below 500 Mbit/s", Mbit(grown))
	}
	l.Down.SetTested(300 * mbit)
	if l.Down.Rate() != grown {
		t.Errorf("slow test cut the grown queue %s → %s", Mbit(grown), Mbit(l.Down.Rate()))
	}
	reached := slices.IndexFunc(rates, func(r uint64) bool { return r >= grown*95/100 })
	t.Logf("tested 300, link 500: queue grew to %s; 95 %% of it after %v of full load", Mbit(grown), time.Duration(reached+1)*2*time.Second)
}

// Канал загрузки стал втрое медленнее очереди (вечер у провайдера), у
// отдачи базы ещё нет: виновата загрузка — её очередь догоняет канал, а
// отдача с подтверждениями базу не получает.
func TestDropBlamesDownloadNotAcks(t *testing.T) {
	l := link(WiredParams())
	l.Down.SetTested(300 * mbit) // очередь 270
	// Первый раунд — до предела процента, через паузу — ниже канала.
	d, u := held(l, Sample{At: t0, DownBps: 120 * mbit, UpBps: 3 * mbit, Delay: 200 * time.Millisecond}, 3)
	if d == "" || u != "" || l.Up.Rate() != 0 {
		t.Errorf("down %q, up %q (up rate %s) — want only download to follow", d, u, Mbit(l.Up.Rate()))
	}
	if r := l.Down.Rate(); r >= 120*mbit {
		t.Errorf("download queue %s, want below the 120 Mbit/s link", Mbit(r))
	}
}

// Повтор находки стенда: оценка в момент первой задержки ошибается —
// на разгоне занижена вдвое (загрузка 28 при канале 60), пока наполняется
// буфер провайдера — завышена (отдача 66 при 60). Обе исправляются быстро.
func TestFirstEstimateCorrected(t *testing.T) {
	for _, tc := range []struct {
		name  string
		first uint64
	}{{"underestimate", 28 * mbit}, {"overestimate", 66 * mbit}} {
		l := link(WiredParams())
		held(l, Sample{At: t0, DownBps: tc.first, UpBps: 1 * mbit, Delay: 300 * time.Millisecond}, confirmRounds)
		rates := run(l, func(int) uint64 { return 60 * mbit }, 90) // 3 минуты
		settle := slices.IndexFunc(rates, func(r uint64) bool { return r >= 50*mbit && r <= 59*mbit })
		if settle < 0 || settle > 30 {
			t.Errorf("%s: first %s on a 60 Mbit/s link — not within 50…59 in a minute (rounds %d): %v", tc.name, Mbit(tc.first), settle, rates[:min(30, len(rates))])
			continue
		}
		t.Logf("%s: %s → in band after %v, last %s", tc.name, Mbit(tc.first), time.Duration(settle+1)*2*time.Second, Mbit(rates[len(rates)-1]))
	}
}

// Разовый скачок задержки при слабом трафике — не предел канала: база не
// появляется, а известная база не опускается до этого трафика.
func TestSingleSpikeIsNotCapacity(t *testing.T) {
	l := link(WiredParams())
	l.Observe(Sample{At: t0, DownBps: 20 * mbit, UpBps: 6 * mbit, Delay: 20 * time.Millisecond})
	l.Observe(Sample{At: t0.Add(2 * time.Second), DownBps: 20 * mbit, UpBps: 6 * mbit, Delay: 2 * time.Millisecond})
	if l.Down.Rate() != 0 || l.Up.Rate() != 0 {
		t.Errorf("one spike set bases: down %s, up %s", Mbit(l.Down.Rate()), Mbit(l.Up.Rate()))
	}
	l = link(WiredParams())
	l.Down.SetTested(500 * mbit)
	l.Observe(Sample{At: t0, DownBps: 20 * mbit, UpBps: 1 * mbit, Delay: 20 * time.Millisecond})
	if base, _ := l.Down.Base(); base != 500*mbit || l.Down.Rate() < 400*mbit {
		t.Errorf("one spike: base %s, rate %s — want base kept, rate ≥ the 80 %% floor", Mbit(base), Mbit(l.Down.Rate()))
	}
	// LTE: предел — половина базы, но один шум — один шаг, не до предела.
	l = link(LTEParams())
	l.Down.SetTested(40 * mbit) // 36
	l.Observe(Sample{At: t0, DownBps: 3 * mbit, Delay: 50 * time.Millisecond})
	if r := l.Down.Rate(); r < 32*mbit {
		t.Errorf("lte spike: rate %s, want one step (32.4)", Mbit(r))
	}
}

// Сотни соединений стартуют разом (торрент, переезд трафика с упавшего
// канала): секунды задержки, пока канал почти пуст. Прошедшее в эти
// раунды — не скорость канала: очередь снижается шагами, а не до него.
func TestBurstAtLightLoadStepsOnly(t *testing.T) {
	l := link(WiredParams())
	l.Down.SetTested(300 * mbit) // 270
	held(l, Sample{At: t0, DownBps: 10 * mbit, UpBps: 2 * mbit, Delay: 260 * time.Millisecond}, 3)
	if r := l.Down.Rate(); r < 200*mbit {
		t.Errorf("wired burst: queue %s, want a couple of steps from 270", Mbit(r))
	}
	lte := link(LTEParams())
	lte.Down.SetTested(44 * mbit) // 39,6
	held(lte, Sample{At: t0, DownBps: 3 * mbit, UpBps: 500_000, Delay: 45 * time.Millisecond}, 3)
	if r := lte.Down.Rate(); r < 30*mbit {
		t.Errorf("lte failover burst: queue %s, want a couple of steps from 39.6", Mbit(r))
	}
}

// Обрыв канала под нагрузкой: пробы молчат, но и трафик падает — это не
// раздутость, ни база, ни скорость очереди не трогаются.
func TestBrokenLinkIsNotBloat(t *testing.T) {
	for _, tested := range []uint64{0, 300 * mbit} {
		l := link(WiredParams())
		l.Down.SetTested(tested)
		before := l.Down.Rate()
		at := t0
		round := func(down, up uint64, lost bool) {
			delay := 2 * time.Millisecond
			if lost {
				delay = time.Second
			}
			l.Observe(Sample{At: at, DownBps: down, UpBps: up, Delay: delay, Lost: lost})
			at = at.Add(2 * time.Second)
		}
		round(20*mbit, 4*mbit, false)
		round(18*mbit, 4*mbit, true) // обрыв посреди раунда: счётчики ещё видят трафик
		round(300_000, 3*mbit, true)
		round(100_000, 2*mbit, true)
		round(20*mbit, 4*mbit, false)
		if l.Down.Rate() != before || l.Up.Rate() != 0 {
			t.Errorf("tested %s: link break changed queues: down %s → %s, up %s", Mbit(tested), Mbit(before), Mbit(l.Down.Rate()), Mbit(l.Up.Rate()))
		}
	}
}

// Канал у провайдера стал вдвое медленнее в простое, очередь загрузки
// осталась прежней. Пришла загрузка — буфер провайдера забивает она, а не
// её подтверждения, упёршиеся в маленькую очередь отдачи.
func TestStaleQueueBlamesDownloadNotAcks(t *testing.T) {
	l := link(WiredParams())
	l.Down.SetTested(535 * mbit) // очередь 481 при канале 250
	l.Up.SetTested(11 * mbit)    // 9,9
	upBefore := l.Up.Rate()
	at := t0
	for range 3 {
		l.Observe(Sample{At: at, DownBps: 250 * mbit, UpBps: 9 * mbit, Delay: 450 * time.Millisecond})
		at = at.Add(2 * time.Second)
	}
	if r := l.Up.Rate(); r != upBefore {
		t.Errorf("acks blamed: upload %s → %s", Mbit(upBefore), Mbit(r))
	}
	if r := l.Down.Rate(); r > 250*mbit {
		t.Errorf("download queue %s after 4 s of bloat — want below the 250 Mbit/s link", Mbit(r))
	}
}

// Вечером канал вдвое медленнее, утром возвращается: очередь догоняет его за
// пару минут, а не ползёт, пока не забудется вечерняя задержка.
func TestRecoversWhenLinkComesBack(t *testing.T) {
	l := link(WiredParams())
	l.Down.SetTested(500 * mbit)
	capacity := func(i int) uint64 {
		if i >= 150 && i < 450 {
			return 250 * mbit
		}
		return 500 * mbit
	}
	rates := run(l, capacity, 900)
	if r := rates[449]; r > 250*mbit*98/100 || r < 200*mbit {
		t.Errorf("evening: %s, want just below 250 Mbit/s", Mbit(r))
	}
	back := slices.IndexFunc(rates[450:], func(r uint64) bool { return r >= 440*mbit })
	if back < 0 || back > 90 {
		t.Errorf("morning: queue reached 440 Mbit/s after %d rounds, want ≤ 3 min (90)", back)
	}
	t.Logf("evening %s, back to 440 after %v", Mbit(rates[449]), time.Duration(back+1)*2*time.Second)
}

// Загрузка упирается в свою заниженную очередь (плохой тест скорости), а
// отдача без базы — настоящая раздача торрента: задержка — и её вина
// тоже, иначе отдача без ограничения забила бы буфер провайдера.
func TestRealUploadBlamedBesideSaturatedDownload(t *testing.T) {
	l := link(WiredParams())
	l.Down.SetTested(10 * mbit) // очередь 9 при настоящих 100
	_, u := held(l, Sample{At: t0, DownBps: 9 * mbit, UpBps: 60 * mbit, Delay: 300 * time.Millisecond}, confirmRounds)
	if u == "" || l.Up.Rate() == 0 {
		t.Errorf("seeding upload not given a queue: %q", u)
	}
	// А подтверждения загрузки (несколько % от неё) — нет.
	l = link(WiredParams())
	l.Down.SetTested(100 * mbit)
	if _, u := held(l, Sample{At: t0, DownBps: 90 * mbit, UpBps: 3 * mbit, Delay: 300 * time.Millisecond}, 3); u != "" {
		t.Errorf("acks got a queue: %q", u)
	}
}
