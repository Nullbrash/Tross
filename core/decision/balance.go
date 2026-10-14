package decision

import (
	"cmp"
	"math"
	"slices"
	"time"

	"tross/core/model"
)

// LinkShare — относительная доля новых соединений, направляемых в канал.
type LinkShare struct {
	Link   model.LinkID
	Weight int
}

// Balance распределяет новые соединения класса по каналам: из основного пула
// политики (Links; пусто — все, кроме Fallback) берутся пригодные каналы, а
// если таких нет — пригодные из Fallback. Селектор:
//   - ordered — первый пригодный (в порядке Links или по приоритету);
//   - lowest_latency — с наименьшей задержкой (с учётом джиттера);
//   - best_throughput — с наибольшей измеренной скоростью;
//   - best_upload — с наибольшей измеренной отдачей;
//   - balanced — все пригодные, вес по измеренной скорости (без замеров — поровну).
//
// Пустой результат — пригодных каналов нет.
func Balance(p model.Policy, links []model.LinkStatus) []LinkShare {
	pool := candidates(p, links, false)
	if len(pool) == 0 {
		pool = candidates(p, links, true)
	}
	if len(pool) == 0 {
		return nil
	}
	switch p.Selector {
	case model.SelectLowestLatency:
		best := slices.MinFunc(pool, func(a, b model.LinkStatus) int { return cmp.Compare(rttOrMax(a), rttOrMax(b)) })
		return []LinkShare{{best.Link.ID, 1}}
	case model.SelectBestThroughput:
		best := slices.MaxFunc(pool, func(a, b model.LinkStatus) int {
			return cmp.Compare(a.Health.Throughput.DownBps, b.Health.Throughput.DownBps)
		})
		return []LinkShare{{best.Link.ID, 1}}
	case model.SelectBestUpload:
		best := slices.MaxFunc(pool, func(a, b model.LinkStatus) int {
			return cmp.Compare(a.Health.Throughput.UpBps, b.Health.Throughput.UpBps)
		})
		return []LinkShare{{best.Link.ID, 1}}
	case model.SelectBalanced:
		return weighted(pool)
	default: // ordered
		return []LinkShare{{pool[0].Link.ID, 1}}
	}
}

// candidates — пригодные каналы пула в порядке предпочтения. MinFunc/MaxFunc
// возвращают первый из равных — поэтому порядок решает и ничьи.
func candidates(p model.Policy, links []model.LinkStatus, fallback bool) []model.LinkStatus {
	byID := make(map[model.LinkID]model.LinkStatus, len(links))
	for _, l := range links {
		byID[l.Link.ID] = l
	}
	var ids []model.LinkID
	switch {
	case fallback:
		ids = p.Fallback
	case len(p.Links) > 0:
		ids = p.Links
	default:
		ordered := slices.Clone(links)
		slices.SortStableFunc(ordered, func(a, b model.LinkStatus) int { return cmp.Compare(a.Link.Priority, b.Link.Priority) })
		for _, l := range ordered {
			if !slices.Contains(p.Fallback, l.Link.ID) {
				ids = append(ids, l.Link.ID)
			}
		}
	}
	var out []model.LinkStatus
	for _, id := range ids {
		if l, ok := byID[id]; ok && l.Health.State.Usable() {
			out = append(out, l)
		}
	}
	return out
}

func rttOrMax(l model.LinkStatus) int64 {
	if l.Health.RTT <= 0 {
		return math.MaxInt64
	}
	return int64(EffectiveRTT(l.Health))
}

// EffectiveRTT — задержка с поправкой на нестабильность: RTT + 2 × джиттер.
// Ровные 12 мс лучше 8 мс со скачками до 30.
func EffectiveRTT(h model.LinkHealth) time.Duration {
	if h.RTT <= 0 {
		return 0
	}
	return h.RTT + 2*h.Jitter
}

// weighted — веса в процентах от суммарной скорости (минимум 1: канал не
// выпадает из распределения из-за округления). Если скорость хоть одного
// канала неизвестна — поровну: сравнивать измеренное с неизмеренным нельзя.
func weighted(pool []model.LinkStatus) []LinkShare {
	var sum uint64
	known := true
	for _, l := range pool {
		if l.Health.Throughput.DownBps == 0 {
			known = false
		}
		sum += l.Health.Throughput.DownBps
	}
	out := make([]LinkShare, 0, len(pool))
	for _, l := range pool {
		w := 1
		if known {
			w = max(1, int(math.Round(float64(l.Health.Throughput.DownBps)*100/float64(sum))))
		}
		out = append(out, LinkShare{l.Link.ID, w})
	}
	return out
}
