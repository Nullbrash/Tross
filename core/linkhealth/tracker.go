// Package linkhealth — состояние канала по раундам активных проб:
// метрики окна (задержка, джиттер, потери) и гистерезис переходов
// up/degraded/down/restricted. Без сети и ОС — переиспользуется на Android.
package linkhealth

import (
	"fmt"
	"math"
	"slices"
	"time"

	"tross/core/model"
)

// Params — пороги. Счётчики — в раундах подряд.
type Params struct {
	Window       int // раундов в окне метрик
	FailAfter    int // раундов без ответов до down (и до restricted)
	RecoverAfter int // удачных раундов до возврата из down/restricted и из degraded
	DegradeAfter int // раундов с плохими метриками до degraded

	// Доля потерь в окне; судится не меньше чем по minLost потерянным пробам.
	DegradedLoss   float64
	DegradedJitter time.Duration // медиана по целям их среднего джиттера в окне
	// Задержка цели «раздута» (bufferbloat), если её средняя ≥ RTTRatio × её
	// минимальной в окне и разница ≥ RTTDelta: одно отношение срабатывает на
	// 1→3 мс. Канал раздут, если раздута хотя бы половина целей.
	RTTRatio float64
	RTTDelta time.Duration

	// HTTPFailAfter — неудачных HTTP-проверок подряд до restricted.
	HTTPFailAfter int
}

func DefaultParams() Params {
	return Params{
		Window: 30, FailAfter: 3, RecoverAfter: 10, DegradeAfter: 3,
		DegradedLoss: 0.05, DegradedJitter: 30 * time.Millisecond,
		RTTRatio: 3, RTTDelta: 20 * time.Millisecond,
		HTTPFailAfter: 2,
	}
}

// Round — итог одного раунда проб канала.
type Round struct {
	At   time.Time
	Sent int      // проб к общим целям
	Recv int      // ответов от общих целей (включая TCP-пробу)
	RTTs []Sample // задержки ответов общих целей
	// Цели, доступные даже в режиме «белых списков» оператора.
	WLSent, WLRecv int
}

// Sample — задержка ответа одной цели. Цель нужна, чтобы джиттер и
// «раздутость» считались по каждой отдельно: цели на разном расстоянии дают
// разные задержки, и вперемешку этот разброс выглядел бы нестабильностью.
type Sample struct {
	Target string
	RTT    time.Duration
}

func (r Round) alive() bool      { return r.Recv > 0 }
func (r Round) restricted() bool { return r.Recv == 0 && r.WLSent > 0 && r.WLRecv > 0 }

// Metrics — метрики окна. RTT и MinRTT — по всем ответам (для показа);
// Jitter — медиана джиттера целей; Bloated — задержка раздута хотя бы у
// половины целей (каждая — относительно своего минимума).
type Metrics struct {
	RTT, MinRTT, Jitter time.Duration
	Loss                float64
	Lost                int // потерянных проб в окне
	Bloated             bool
	BloatDetail         string // для причины degraded: сколько целей и худшая
}

// Tracker — состояние одного канала. Не потокобезопасен: вызывающий
// сериализует Observe.
type Tracker struct {
	p      Params
	window []Round
	state  model.LinkState
	since  time.Time
	reason string

	good, bad, restr, deg, ok int // текущие серии раундов

	httpFail       int  // неудачных HTTP-проверок подряд
	httpRestricted bool // restricted выставлен HTTP-проверкой, а не пробами
}

func NewTracker(p Params) *Tracker {
	return &Tracker{p: p, state: model.LinkStateUnknown}
}

func (t *Tracker) State() (model.LinkState, time.Time, string) { return t.state, t.since, t.reason }

// Observe учитывает раунд; changed — состояние сменилось.
func (t *Tracker) Observe(r Round) (Metrics, bool) {
	t.window = append(t.window, r)
	if over := len(t.window) - t.p.Window; over > 0 {
		t.window = t.window[over:]
	}
	prev := t.state

	switch {
	case r.alive():
		t.bad, t.restr = 0, 0
		t.good++
		switch t.state {
		case model.LinkStateUnknown:
			// Быстрый старт: при запуске демона канал не ждёт RecoverAfter.
			t.set(r.At, model.LinkStateUp, "first reply")
		case model.LinkStateDown, model.LinkStateRestricted:
			// Ограничение по HTTP снимает только удачная HTTP-проверка: ping
			// при нём идёт, и иначе канал мигал бы restricted ↔ up.
			if t.good >= t.p.RecoverAfter && !t.httpRestricted {
				// Потери времени простоя не должны держать канал в degraded.
				t.window = t.window[len(t.window)-t.good:]
				t.deg, t.ok = 0, 0
				t.set(r.At, model.LinkStateUp, fmt.Sprintf("recovered after %d good rounds", t.good))
			}
		}
	case r.restricted():
		t.good, t.deg, t.ok = 0, 0, 0
		t.restr++
		t.bad++
		if t.state != model.LinkStateRestricted && t.restr >= t.p.FailAfter {
			t.set(r.At, model.LinkStateRestricted, fmt.Sprintf("only whitelist targets reply for %d rounds", t.restr))
		}
	default:
		t.good, t.restr, t.deg, t.ok = 0, 0, 0, 0
		t.bad++
		if t.state != model.LinkStateDown && t.bad >= t.p.FailAfter {
			// После обрыва HTTP проверяется заново: прошлый вердикт устарел.
			t.httpFail, t.httpRestricted = 0, false
			t.set(r.At, model.LinkStateDown, fmt.Sprintf("no replies for %d rounds", t.bad))
		}
	}

	m := t.metrics()
	if r.alive() && (t.state == model.LinkStateUp || t.state == model.LinkStateDegraded) && t.state == prev {
		if why := t.degradedReason(m); why != "" {
			t.ok = 0
			t.deg++
			if t.state == model.LinkStateUp && t.deg >= t.p.DegradeAfter {
				t.set(r.At, model.LinkStateDegraded, why)
			}
		} else {
			t.deg = 0
			t.ok++
			if t.state == model.LinkStateDegraded && t.ok >= t.p.RecoverAfter {
				t.set(r.At, model.LinkStateUp, "metrics back to normal")
			}
		}
	}
	return m, t.state != prev
}

// ObserveHTTP учитывает итог HTTP-проверки связи (ответ проверки подключения
// вместо подмены или тишины); changed — состояние сменилось.
func (t *Tracker) ObserveHTTP(at time.Time, ok bool, why string) bool {
	prev := t.state
	if ok {
		t.httpFail = 0
		if t.httpRestricted {
			t.httpRestricted = false
			if t.state == model.LinkStateRestricted {
				t.deg, t.ok = 0, 0
				t.set(at, model.LinkStateUp, "http check passed")
			}
		}
		return t.state != prev
	}
	t.httpFail++
	if t.httpFail >= t.p.HTTPFailAfter && (t.state == model.LinkStateUp || t.state == model.LinkStateDegraded) {
		t.httpRestricted = true
		t.set(at, model.LinkStateRestricted, fmt.Sprintf("http check failed %d times: %s", t.httpFail, why))
	}
	return t.state != prev
}

// HTTPRelevant — есть ли смысл в HTTP-проверке сейчас (канал жив по пробам
// или ограничен именно по HTTP).
func (t *Tracker) HTTPRelevant() bool {
	return t.state.Usable() || t.httpRestricted
}

func (t *Tracker) set(at time.Time, s model.LinkState, why string) {
	t.state, t.since, t.reason = s, at, why
}

func (t *Tracker) degradedReason(m Metrics) string {
	switch {
	case m.Loss >= t.p.DegradedLoss && m.Lost >= minLost:
		return fmt.Sprintf("loss %.1f%%", m.Loss*100)
	case m.Jitter >= t.p.DegradedJitter:
		return fmt.Sprintf("jitter %v", m.Jitter.Round(time.Millisecond))
	case m.Bloated:
		return "rtt " + m.BloatDetail
	}
	return ""
}

// minLost — в молодом окне (после старта или восстановления) одна случайная
// потеря уже даёт ≥ 5 %; на полном окне порог и так требует 5–6 потерь.
const minLost = 2

// bloatMinSamples — меньше ответов цели в окне — по ней «раздутость» не
// судим: среднее из пары значений слишком шумное.
const bloatMinSamples = 3

func (t *Tracker) metrics() Metrics {
	var m Metrics
	var sent, recv, n int
	var sum time.Duration
	m.MinRTT = time.Duration(math.MaxInt64)
	perTarget := map[string][]time.Duration{}
	var targets []string
	for _, r := range t.window {
		sent += r.Sent
		recv += min(r.Recv, r.Sent)
		for _, s := range r.RTTs {
			sum += s.RTT
			n++
			m.MinRTT = min(m.MinRTT, s.RTT)
			if _, ok := perTarget[s.Target]; !ok {
				targets = append(targets, s.Target)
			}
			perTarget[s.Target] = append(perTarget[s.Target], s.RTT)
		}
	}
	if sent > 0 {
		m.Loss = 1 - float64(recv)/float64(sent)
		m.Lost = sent - recv
	}
	if n == 0 {
		m.MinRTT = 0
		return m
	}
	m.RTT = sum / time.Duration(n)

	var jitters []time.Duration
	considered, bloated := 0, 0
	worst, worstAvg, worstMin := "", time.Duration(0), time.Duration(0)
	for _, tg := range targets {
		rtts := perTarget[tg]
		if len(rtts) >= 2 {
			var js time.Duration
			for k := 1; k < len(rtts); k++ {
				d := rtts[k] - rtts[k-1]
				js += max(d, -d)
			}
			jitters = append(jitters, js/time.Duration(len(rtts)-1))
		}
		if len(rtts) < bloatMinSamples {
			continue
		}
		considered++
		lo, total := rtts[0], time.Duration(0)
		for _, d := range rtts {
			lo = min(lo, d)
			total += d
		}
		avg := total / time.Duration(len(rtts))
		if float64(avg) >= t.p.RTTRatio*float64(lo) && avg-lo >= t.p.RTTDelta {
			bloated++
			if avg-lo > worstAvg-worstMin {
				worst, worstAvg, worstMin = tg, avg, lo
			}
		}
	}
	m.Jitter = median(jitters)
	if considered > 0 && bloated*2 >= considered {
		m.Bloated = true
		m.BloatDetail = fmt.Sprintf("bloated on %d/%d targets (%s %v vs min %v)", bloated, considered,
			worst, worstAvg.Round(time.Millisecond), worstMin.Round(time.Millisecond))
	}
	return m
}

// median — медиана (для чётного числа — среднее двух средних); пусто — 0.
func median(v []time.Duration) time.Duration {
	if len(v) == 0 {
		return 0
	}
	s := slices.Clone(v)
	slices.Sort(s)
	if len(s)%2 == 1 {
		return s[len(s)/2]
	}
	return (s[len(s)/2-1] + s[len(s)/2]) / 2
}
