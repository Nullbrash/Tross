package linkhealth

import (
	"strings"
	"testing"
	"time"

	"tross/core/model"
)

var t0 = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

// rounds — сквозной номер раунда каждого трекера (время раунда = t0 + 2 с × номер).
var rounds = map[*Tracker]int{}

// feed подаёт раунды по коду: g — хороший (3/3, rtt 8 мс), x — без ответов,
// w — отвечают только цели белого списка, l — 1 из 3 потерян, b — раздутая
// задержка; возвращает состояние после каждого раунда.
func feed(tr *Tracker, codes string) []model.LinkState {
	var out []model.LinkState
	for _, c := range codes {
		r := Round{At: t0.Add(time.Duration(rounds[tr]) * 2 * time.Second), Sent: 3, WLSent: 1}
		rounds[tr]++
		ms := func(v ...int) []Sample {
			var d []Sample
			for i, x := range v {
				d = append(d, Sample{Target: string(rune('a' + i)), RTT: time.Duration(x) * time.Millisecond})
			}
			return d
		}
		switch c {
		case 'g':
			r.Recv, r.RTTs, r.WLRecv = 3, ms(8, 8, 9), 1
		case 'x':
		case 'w':
			r.WLRecv = 1
		case 'l':
			r.Recv, r.RTTs, r.WLRecv = 2, ms(8, 9), 1
		case 'b':
			r.Recv, r.RTTs, r.WLRecv = 3, ms(90, 95, 100), 1
		}
		tr.Observe(r)
		s, _, _ := tr.State()
		out = append(out, s)
	}
	return out
}

func last(s []model.LinkState) model.LinkState { return s[len(s)-1] }

func TestFastStartAndFail(t *testing.T) {
	tr := NewTracker(DefaultParams())
	st := feed(tr, "g")
	if st[0] != model.LinkStateUp {
		t.Fatalf("first reply must bring link up, got %s", st[0])
	}
	st = feed(tr, "xx")
	if last(st) != model.LinkStateUp {
		t.Fatalf("two lost rounds must not drop the link, got %s", last(st))
	}
	st = feed(tr, "x")
	if last(st) != model.LinkStateDown {
		t.Fatalf("third lost round must drop the link, got %s", last(st))
	}
	_, since, why := tr.State()
	// Раунды g,x,x,x — down на 4-м (номер 3, 6 с).
	if since != t0.Add(3*2*time.Second) || !strings.Contains(why, "3 rounds") {
		t.Fatalf("since=%v why=%q", since, why)
	}
}

func TestRecoveryNeedsRecoverAfter(t *testing.T) {
	tr := NewTracker(DefaultParams())
	feed(tr, "gxxx")
	st := feed(tr, "ggggggggg") // 9 хороших
	if last(st) != model.LinkStateDown {
		t.Fatalf("9 good rounds must not recover, got %s", last(st))
	}
	st = feed(tr, "g")
	if last(st) != model.LinkStateUp {
		t.Fatalf("10th good round must recover, got %s", last(st))
	}
	// Окно очищено от простоя: канал сразу не становится degraded.
	st = feed(tr, "gggg")
	if last(st) != model.LinkStateUp {
		t.Fatalf("after recovery link must stay up, got %s", last(st))
	}
}

func TestFlappingStaysDown(t *testing.T) {
	tr := NewTracker(DefaultParams())
	feed(tr, "gxxx")
	st := feed(tr, strings.Repeat("gggggx", 6))
	for i, s := range st {
		if s != model.LinkStateDown {
			t.Fatalf("flapping link recovered at round %d (%s)", i, s)
		}
	}
}

func TestDegradedByLossAndBack(t *testing.T) {
	tr := NewTracker(DefaultParams())
	feed(tr, strings.Repeat("g", 10))
	// 1 из 3 потерян каждый раунд: на фоне 10 чистых раундов 5 % превышены со
	// 2-го такого раунда, и ещё DegradeAfter=3 подряд — degraded на 4-м.
	st := feed(tr, "lll")
	if last(st) != model.LinkStateUp {
		t.Fatalf("3 lossy rounds must not degrade yet, got %v", st)
	}
	st = feed(tr, "l")
	if last(st) != model.LinkStateDegraded {
		t.Fatalf("persistent loss must degrade, got %v", st)
	}
	_, _, why := tr.State()
	if !strings.HasPrefix(why, "loss") {
		t.Fatalf("reason = %q", why)
	}
	// Пока потери в окне ≥ 5 %, канал остаётся degraded; выходит после RecoverAfter
	// раундов с нормальными метриками.
	st = feed(tr, strings.Repeat("g", 40))
	if last(st) != model.LinkStateUp {
		t.Fatalf("clean rounds must restore up, got %s", last(st))
	}
}

func TestDegradedByBloat(t *testing.T) {
	tr := NewTracker(DefaultParams())
	feed(tr, strings.Repeat("g", 10))
	// Средняя окна дорастает до 3× минимума лишь на 3-м раунде раздутой
	// задержки — ловится устойчивый bufferbloat, а не единичный скачок.
	st := feed(tr, "bbbb")
	if last(st) != model.LinkStateUp {
		t.Fatalf("short bloat must not degrade, got %v", st)
	}
	st = feed(tr, "b")
	if last(st) != model.LinkStateDegraded {
		t.Fatalf("bloated rtt must degrade, got %v", st)
	}
}

func TestShortLossBurstDoesNotDegrade(t *testing.T) {
	p := DefaultParams()
	tr := NewTracker(p)
	feed(tr, strings.Repeat("g", 30))
	// Один раунд с потерей 1/3 в окне из 30 раундов = 1,1 % < 5 %.
	st := feed(tr, "lggg")
	for _, s := range st {
		if s != model.LinkStateUp {
			t.Fatalf("single lossy round degraded the link: %v", st)
		}
	}
}

func TestRestrictedWhitelist(t *testing.T) {
	tr := NewTracker(DefaultParams())
	feed(tr, "ggg")
	st := feed(tr, "www")
	if last(st) != model.LinkStateRestricted {
		t.Fatalf("whitelist-only replies must mark restricted, got %v", st)
	}
	if model.LinkStateRestricted.Usable() {
		t.Fatal("restricted must not be usable for general traffic")
	}
	// Полная тишина после restricted — down.
	st = feed(tr, "xxx")
	if last(st) != model.LinkStateDown {
		t.Fatalf("silence after restricted must be down, got %s", last(st))
	}
	st = feed(tr, strings.Repeat("g", 10))
	if last(st) != model.LinkStateUp {
		t.Fatalf("recovery from restricted/down, got %s", last(st))
	}
}

func TestHTTPCheckRestrictsAndRecovers(t *testing.T) {
	tr := NewTracker(DefaultParams())
	feed(tr, "ggg")
	at := t0.Add(time.Minute)
	if tr.ObserveHTTP(at, false, "portal") {
		t.Fatal("one failed HTTP check must not restrict")
	}
	if !tr.ObserveHTTP(at, false, "portal") {
		t.Fatal("second failed HTTP check must restrict")
	}
	if s, _, why := tr.State(); s != model.LinkStateRestricted || !strings.Contains(why, "portal") {
		t.Fatalf("state %s, reason %q", s, why)
	}
	// Ping идёт — но ограничение по HTTP не снимается пробами.
	st := feed(tr, strings.Repeat("g", 15))
	if last(st) != model.LinkStateRestricted {
		t.Fatalf("good ICMP rounds lifted HTTP restriction: %s", last(st))
	}
	if !tr.HTTPRelevant() {
		t.Fatal("HTTP check must keep running while restricted by HTTP")
	}
	if !tr.ObserveHTTP(at, true, "") {
		t.Fatal("passing HTTP check must lift restriction")
	}
	if s, _, _ := tr.State(); s != model.LinkStateUp {
		t.Fatalf("after HTTP pass: %s", s)
	}
}

func TestHTTPVerdictResetAfterOutage(t *testing.T) {
	tr := NewTracker(DefaultParams())
	feed(tr, "g")
	tr.ObserveHTTP(t0, false, "x")
	tr.ObserveHTTP(t0, false, "x")
	feed(tr, "xxx")
	if s, _, _ := tr.State(); s != model.LinkStateDown {
		t.Fatalf("state %s, want down", s)
	}
	if tr.HTTPRelevant() {
		t.Fatal("down link: HTTP check is pointless")
	}
	st := feed(tr, strings.Repeat("g", 10))
	if last(st) != model.LinkStateUp {
		t.Fatalf("after outage the stale HTTP verdict must not block recovery: %s", last(st))
	}
	// Одна неудача после обрыва — ещё не restricted (счётчик сброшен).
	if tr.ObserveHTTP(t0, false, "x") {
		t.Fatal("HTTP fail counter must restart after outage")
	}
}

func TestMetrics(t *testing.T) {
	tr := NewTracker(DefaultParams())
	tr.Observe(Round{At: t0, Sent: 2, Recv: 2, RTTs: []Sample{{"a", 10 * time.Millisecond}, {"b", 20 * time.Millisecond}}})
	m, _ := tr.Observe(Round{At: t0.Add(2 * time.Second), Sent: 2, Recv: 1, RTTs: []Sample{{"a", 30 * time.Millisecond}}})
	// Джиттер — только по цели a (10 → 30); у b один ответ, разница a−b не в счёт.
	if m.RTT != 20*time.Millisecond || m.MinRTT != 10*time.Millisecond || m.Jitter != 20*time.Millisecond {
		t.Fatalf("metrics = %+v", m)
	}
	if m.Loss != 0.25 {
		t.Fatalf("loss = %v, want 0.25", m.Loss)
	}
}

// samples строит раунд с полным ответом: задержки целей a, b, c… в мс.
func samples(v ...float64) []Sample {
	var d []Sample
	for i, x := range v {
		d = append(d, Sample{Target: string(rune('a' + i)), RTT: time.Duration(x * float64(time.Millisecond))})
	}
	return d
}

// Цели на разном расстоянии и с разной (но своей стабильной) задержкой — не
// джиттер и не «раздутость»; скачущая задержка одной и той же цели — да.
func TestPerTargetJitterAndBloat(t *testing.T) {
	// step — 4 раунда с задержками before, затем 6 с after: устойчивый рост
	// задержки (bufferbloat), почти не дающий джиттера.
	step := func(before, after []float64) [][]float64 {
		var r [][]float64
		for i := range 10 {
			r = append(r, before)
			if i >= 4 {
				r[i] = after
			}
		}
		return r
	}
	cases := []struct {
		name    string
		rounds  [][]float64 // задержки целей a, b, c по раундам
		jitter  time.Duration
		bloated bool
		state   model.LinkState
	}{
		{"near and far stable", [][]float64{{10, 60}, {10, 60}, {11, 61}, {10, 60}}, 2 * time.Millisecond / 3, false, model.LinkStateUp},
		// Медиана по целям a (80) и b (0); a заодно раздута — это половина целей.
		{"jumping target", [][]float64{{10, 10}, {90, 10}, {10, 10}, {90, 10}, {10, 10}}, 40 * time.Millisecond, true, model.LinkStateDegraded},
		{"one of three bloated", step([]float64{10, 20, 30}, []float64{10, 20, 300}), 0, false, model.LinkStateUp},
		// Джиттер a — 10, b — 20, c — 0: деградирует именно по «раздутости».
		{"two of three bloated", step([]float64{10, 20, 30}, []float64{100, 200, 30}), 10 * time.Millisecond, true, model.LinkStateDegraded},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tr := NewTracker(DefaultParams())
			var m Metrics
			for i, r := range c.rounds {
				m, _ = tr.Observe(Round{At: t0.Add(time.Duration(i) * 2 * time.Second), Sent: len(r), Recv: len(r), RTTs: samples(r...)})
			}
			if m.Jitter != c.jitter {
				t.Errorf("jitter = %v, want %v", m.Jitter, c.jitter)
			}
			if m.Bloated != c.bloated {
				t.Errorf("bloated = %v (%s), want %v", m.Bloated, m.BloatDetail, c.bloated)
			}
			if s, _, reason := tr.State(); s != c.state {
				t.Errorf("state = %v (%s), want %v", s, reason, c.state)
			}
		})
	}
}
