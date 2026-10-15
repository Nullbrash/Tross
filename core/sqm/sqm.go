// Package sqm — очереди CAKE каналов: скорость очереди (база × процент) и
// корзины приоритетов. Очередь должна стоять чуть ниже настоящей скорости
// канала — иначе пакеты копятся у провайдера и задержка растёт под
// нагрузкой; процент подстраивается по росту задержки под нагрузкой.
package sqm

import (
	"errors"
	"fmt"
	"time"

	"tross/core/model"
)

// Tin — корзина CAKE diffserv4 в порядке приоритета; значение — номер для
// выбора корзины по метке пакета (CAKE fwmark: 1 — Bulk … 4 — Voice,
// 0 — по DSCP, то есть Best effort).
type Tin uint8

const (
	TinNone Tin = iota
	TinBulk
	TinBestEffort
	TinVideo
	TinVoice
)

func (t Tin) String() string {
	return [...]string{"none", "bulk", "best_effort", "video", "voice"}[t]
}

// TinFor — корзина приоритета класса: голос (игры, звонки) — первенство до
// ~25 % канала, видео — до ~50 %, обычное, фон (загрузки — минимум ~6 %).
func TinFor(p model.Priority) Tin {
	switch p {
	case model.PriorityHigh:
		return TinVoice
	case model.PriorityVideo:
		return TinVideo
	case model.PriorityLow:
		return TinBulk
	}
	return TinBestEffort
}

// Basis — откуда взята база (скорость канала).
type Basis string

const (
	BasisNone    Basis = ""
	BasisManual  Basis = "manual"  // sqm.*_mbit из конфига — замеры её не меняют
	BasisTest    Basis = "test"    // тест скорости с открытой очередью
	BasisPassive Basis = "passive" // насыщение канала, увиденное по задержке
	// BasisRestored — скорость очереди, стоявшая в ядре до запуска демона
	// (очереди переживают его остановку); ведёт себя как пассивная.
	BasisRestored Basis = "restored"
)

// movable — база не из замера и не из конфига: её можно двигать по задержке.
func (b Basis) movable() bool { return b == BasisPassive || b == BasisRestored }

// Params — настройки одного направления одного канала.
type Params struct {
	// Start, Min, Max — процент от базы (доли 0..1): начальный и пределы
	// автоподстройки.
	Start, Min, Max float64
	// Auto — подстраивать процент; иначе всегда Start.
	Auto bool
	// Delay — прирост задержки над базовой, выше которого считается, что
	// очередь копится у провайдера.
	Delay time.Duration
	// Load — доля скорости очереди, с которой канал «под нагрузкой»;
	// Saturated — «упирается в очередь».
	Load, Saturated float64
	// StepDown быстрее StepUp: раздутая очередь бьёт по игре сразу, а
	// недобор скорости терпит.
	StepDown, StepUp float64
	// DownEvery, UpEvery — не чаще: снижение и рост после любой смены.
	DownEvery, UpEvery time.Duration
	// BaseGrow — шаг роста базы из пассивной оценки (она — «не меньше чем»).
	BaseGrow float64
	// MinRate — нижний предел скорости очереди и минимальный трафик, по
	// которому вообще судят о насыщении, бит/с.
	MinRate uint64
}

func defaults(min, max float64, delay time.Duration) Params {
	return Params{
		Start: 0.90, Min: min, Max: max, Auto: true, Delay: delay,
		Load: 0.75, Saturated: 0.90,
		StepDown: 0.02, StepUp: 0.005,
		DownEvery: 10 * time.Second, UpEvery: 30 * time.Second,
		BaseGrow: 1.05, MinRate: 1_000_000,
	}
}

// WiredParams — проводной канал: 90 %, пределы 80–97 % (решение
// пользователя); 15 мс — прирост, допустимый критерием этапа.
func WiredParams() Params { return defaults(0.80, 0.97, 15*time.Millisecond) }

// LTEParams — LTE: скорость плавает сильнее — пределы 50–95 %, задержка
// сотовой сети шумнее — порог выше.
func LTEParams() Params { return defaults(0.50, 0.95, 30*time.Millisecond) }

// ParamsFor — значения по умолчанию для вида канала.
func ParamsFor(k model.LinkKind) Params {
	if k == model.LinkKindLTE {
		return LTEParams()
	}
	return WiredParams()
}

func (p Params) Validate() error {
	var errs []error
	if p.Min <= 0 || p.Max > 1 || p.Min > p.Start || p.Start > p.Max {
		errs = append(errs, fmt.Errorf("want 0 < min ≤ start ≤ max ≤ 100 %%, got %.0f/%.0f/%.0f %%", p.Min*100, p.Start*100, p.Max*100))
	}
	if p.Delay <= 0 || p.Load <= 0 || p.Saturated < p.Load || p.Saturated > 1 {
		errs = append(errs, errors.New("bad delay or load thresholds"))
	}
	if p.StepDown <= 0 || p.StepUp <= 0 || p.BaseGrow <= 1 || p.DownEvery <= 0 || p.UpEvery <= 0 {
		errs = append(errs, errors.New("bad adjustment steps"))
	}
	return errors.Join(errs...)
}

// Sample — один раунд наблюдения за каналом.
type Sample struct {
	At time.Time
	// DownBps, UpBps — текущий трафик по направлениям, бит/с.
	DownBps, UpBps uint64
	// Delay — прирост задержки канала над базовой (минимальной) в этом
	// раунде; задержка общая для обоих направлений.
	Delay time.Duration
}

// Link — очереди обоих направлений канала. Рост задержки один на канал, и
// чьё направление виновато, решает трафик: то, что упирается в свою
// очередь, иначе — самое нагруженное. Не потокобезопасен.
type Link struct{ Down, Up *Shaper }

// Observe — раунд наблюдения; причины изменений по направлениям ("" — без
// изменений).
func (l *Link) Observe(x Sample) (down, up string) {
	d, u := l.Down.load(x.DownBps), l.Up.load(x.UpBps)
	if x.Delay > l.Down.p.Delay || x.Delay > l.Up.p.Delay {
		blameDown, blameUp := d >= l.Down.p.Load, u >= l.Up.p.Load
		if blameDown && blameUp && (l.Down.base == 0 || l.Up.base == 0) {
			// Без базы «загрузка» неизвестна — заметный трафик похож на
			// насыщение в обе стороны, хотя отдача при загрузке — одни
			// подтверждения: их база урезала бы отдачу до пары Мбит/с.
			// Виновато направление с известной загрузкой, а из неизвестных —
			// с бо́льшим трафиком; другое разберётся в следующих раундах.
			switch {
			case l.Down.base == 0 && l.Up.base == 0:
				blameDown, blameUp = x.DownBps >= x.UpBps, x.UpBps > x.DownBps
			case l.Down.base == 0:
				blameDown = false
			default:
				blameUp = false
			}
		}
		if !blameDown && !blameUp {
			// Ни одно направление не упирается в очередь, а задержка растёт:
			// канал стал медленнее очереди (или очереди ещё нет) — виновато
			// более нагруженное направление.
			blameDown, blameUp = d >= u, u > d
		}
		if blameDown && x.Delay > l.Down.p.Delay {
			down = l.Down.overload(x.At, x.DownBps, x.Delay)
		}
		if blameUp && x.Delay > l.Up.p.Delay {
			up = l.Up.overload(x.At, x.UpBps, x.Delay)
		}
		return down, up
	}
	if x.Delay <= l.Down.p.Delay/2 {
		down = l.Down.headroom(x.At, d)
	}
	if x.Delay <= l.Up.p.Delay/2 {
		up = l.Up.headroom(x.At, u)
	}
	return down, up
}

// Shaper — скорость очереди одного направления одного канала.
type Shaper struct {
	p          Params
	base       uint64
	basis      Basis
	frac       float64
	lastChange time.Time
}

// NewShaper — manualBps > 0 — база из конфига; 0 — до замера очередь без
// ограничения скорости (корзины и деление по устройствам безвредны, но
// работают, только когда очередь копится у нас).
func NewShaper(p Params, manualBps uint64) *Shaper {
	s := &Shaper{p: p, frac: p.Start}
	if manualBps > 0 {
		s.base, s.basis = manualBps, BasisManual
	}
	return s
}

// Rate — скорость очереди, бит/с; 0 — без ограничения.
func (s *Shaper) Rate() uint64 {
	if s.base == 0 {
		return 0
	}
	return max(uint64(float64(s.base)*s.frac), s.p.MinRate)
}

func (s *Shaper) Base() (uint64, Basis) { return s.base, s.basis }
func (s *Shaper) Fraction() float64     { return s.frac }

// Restore — скорость очереди, уже стоящая в ядре: перезапуск демона не
// должен снимать защиту до новых замеров. Ручная база важнее.
func (s *Shaper) Restore(rateBps uint64) {
	if s.basis == BasisManual || rateBps == 0 || s.base != 0 {
		return
	}
	s.base, s.basis = uint64(float64(rateBps)/s.frac), BasisRestored
}

// SetTested — замер скорости канала с открытой очередью; база из конфига
// важнее замеров. true — скорость очереди изменилась.
func (s *Shaper) SetTested(bps uint64) bool {
	if s.basis == BasisManual || bps == 0 {
		return false
	}
	before := s.Rate()
	s.base, s.basis = bps, BasisTest
	return s.Rate() != before
}

// Busy — канал заметно нагружен (хоть одно направление занимает половину
// своей очереди): базовая задержка в это время не ползёт вверх.
func (l *Link) Busy(downBps, upBps uint64) bool {
	return l.Down.load(downBps) >= 0.5 || l.Up.load(upBps) >= 0.5
}

// load — доля скорости очереди, занятая трафиком; без ограничения —
// неизвестна: любой заметный трафик может быть насыщением канала.
func (s *Shaper) load(bps uint64) float64 {
	if bps < s.p.MinRate {
		return 0
	}
	if r := s.Rate(); r > 0 {
		return float64(bps) / float64(r)
	}
	return 1
}

// overload — задержка выросла по вине этого направления.
func (s *Shaper) overload(at time.Time, bps uint64, delay time.Duration) string {
	if bps < s.p.MinRate {
		return ""
	}
	if s.base == 0 {
		// Без ограничения очередь у нас не копится: рост задержки при
		// заметном трафике — канал заполнен, это и есть его скорость.
		s.base, s.basis, s.frac, s.lastChange = bps, BasisPassive, s.p.Start, at
		return fmt.Sprintf("passive base %s: delay +%v at full link", Mbit(bps), delay)
	}
	if !s.p.Auto || at.Sub(s.lastChange) < s.p.DownEvery {
		return ""
	}
	rate := s.Rate()
	switch {
	case float64(bps) < float64(rate)*s.p.Load && s.basis.movable():
		// Канал стал заметно медленнее очереди (у LTE так бывает): шагами
		// процента не догнать — прошедший трафик и есть новая скорость.
		s.base = bps
	case s.frac > s.p.Min:
		s.frac = max(s.frac-s.p.StepDown, s.p.Min)
	case s.basis.movable():
		s.base = max(uint64(float64(s.base)*(1-s.p.StepDown)), s.p.MinRate)
	default:
		// База из теста или конфига, процент уже на пределе — дальше
		// пользователь сам ограничил.
		return ""
	}
	return s.changed(at, rate, "delay +"+delay.String()+" under load")
}

// headroom — задержка ровная: если направление упирается в очередь,
// скорости можно прибавить.
func (s *Shaper) headroom(at time.Time, load float64) string {
	if s.base == 0 || !s.p.Auto || load < s.p.Saturated || at.Sub(s.lastChange) < s.p.UpEvery {
		return ""
	}
	rate := s.Rate()
	switch {
	case s.frac < s.p.Max:
		s.frac = min(s.frac+s.p.StepUp, s.p.Max)
	case s.basis.movable():
		// Пассивная оценка — «не меньше чем»: канал тянет больше.
		s.base = uint64(float64(s.base) * s.p.BaseGrow)
	default:
		return ""
	}
	return s.changed(at, rate, "link full, delay flat")
}

func (s *Shaper) changed(at time.Time, before uint64, why string) string {
	s.lastChange = at
	if s.Rate() == before {
		return ""
	}
	return fmt.Sprintf("%s → %s (%.1f %% of %s base %s): %s", Mbit(before), Mbit(s.Rate()), s.frac*100, s.basis, Mbit(s.base), why)
}

// Mbit — скорость для журналов и причин.
func Mbit(bps uint64) string { return fmt.Sprintf("%.1f Mbit/s", float64(bps)/1e6) }
