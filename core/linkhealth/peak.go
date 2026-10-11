package linkhealth

import "time"

// PeakTracker — наибольшая скорость, реально прошедшая через канал за
// последние 24 часа (почасовые корзины). Пассивный замер: трафика не тратит.
type PeakTracker struct {
	b [24]struct {
		hour     int64 // часов от эпохи Unix; 0 — корзина пуста
		down, up uint64
	}
}

func (p *PeakTracker) Add(at time.Time, downBps, upBps uint64) {
	h := at.Unix() / 3600
	c := &p.b[h%24]
	if c.hour != h {
		c.hour, c.down, c.up = h, 0, 0
	}
	c.down = max(c.down, downBps)
	c.up = max(c.up, upBps)
}

func (p *PeakTracker) Peak(now time.Time) (down, up uint64) {
	h := now.Unix() / 3600
	for _, c := range p.b {
		if c.hour != 0 && h-c.hour < 24 {
			down, up = max(down, c.down), max(up, c.up)
		}
	}
	return down, up
}
