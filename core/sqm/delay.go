package sqm

import (
	"slices"
	"time"
)

// Delay — прирост задержки канала над базовой, по каждой цели отдельно:
// цели на разном расстоянии (Москва и Стокгольм), общий минимум смешал бы
// их. Минимум окна монитора не годится: под долгой нагрузкой окно целиком
// «раздуто», и минимум растёт вместе с очередью.
type Delay struct {
	base map[string]time.Duration
}

// driftDiv — в простое база ползёт к текущей задержке на 1/driftDiv
// разницы за раунд (~1 мин при раунде 2 с): маршрут к цели мог стать
// длиннее. Под нагрузкой не ползёт — иначе очередь стала бы «нормой».
const driftDiv = 32

// Observe — раунд: задержки по целям; loaded — канал нагружен (база не
// ползёт). ok=false — ни одна цель не ответила.
func (d *Delay) Observe(rtts map[string]time.Duration, loaded bool) (time.Duration, bool) {
	if d.base == nil {
		d.base = map[string]time.Duration{}
	}
	var deltas []time.Duration
	for target, rtt := range rtts {
		b, ok := d.base[target]
		switch {
		case !ok || rtt < b:
			b = rtt
		case !loaded:
			b += (rtt - b) / driftDiv
		}
		d.base[target] = b
		deltas = append(deltas, rtt-b)
	}
	if len(deltas) == 0 {
		return 0, false
	}
	slices.Sort(deltas)
	// Медиана: одна цель с плохим путём не выдаёт «раздутость» канала.
	return deltas[len(deltas)/2], true
}
