package dpi

import (
	"cmp"
	"slices"
	"time"
)

// Method — как открывать домен на канале.
type Method string

const (
	MethodDirect Method = "direct"
	// MethodDPI — с обходом движком (Verdict.Strategy).
	MethodDPI Method = "direct_dpi"
	// MethodElsewhere — на этом канале не открыть: другой канал или прокси.
	MethodElsewhere Method = "elsewhere"
	// MethodUnknown — проверить не удалось (канал плох) — повторить позже.
	MethodUnknown Method = "unknown"
)

// Verdict — решение по домену на канале.
type Verdict struct {
	Method    Method    `json:"method"`
	Strategy  string    `json:"strategy,omitempty"`
	Kind      BlockKind `json:"kind"`
	CheckedAt time.Time `json:"checked_at"`
}

// Tried — попытка со стратегией.
type Tried struct {
	Strategy string
	Attempt  Attempt
}

// Decide — решение по попытке напрямую, контрольной и попыткам со
// стратегиями (в порядке перебора): первая, с которой домен открылся
// полностью, — она; не помогла ни одна или блок не по силам движку —
// «в другом месте».
func Decide(direct, control Attempt, tried []Tried, at time.Time) Verdict {
	kind := Classify(direct, control)
	v := Verdict{Kind: kind, CheckedAt: at}
	switch {
	case kind == KindLinkBad:
		v.Method = MethodUnknown
	case kind == KindNone:
		v.Method = MethodDirect
	case !kind.Helps():
		v.Method = MethodElsewhere
	default:
		v.Method = MethodElsewhere
		for _, t := range tried {
			if Classify(t.Attempt, control) == KindNone {
				v.Method, v.Strategy = MethodDPI, t.Strategy
				break
			}
		}
	}
	return v
}

// Score — итог стратегии на канале по проверкам доменов-маркеров.
type Score struct {
	Strategy string    `json:"strategy"`
	Opened   int       `json:"opened"`
	Failed   int       `json:"failed"`
	LastOK   time.Time `json:"last_ok,omitzero"`
}

// Ranking — стратегии канала по убыванию пользы: больше открытых маркеров,
// меньше неудач, недавний успех; при равенстве — порядок каталога (проще —
// раньше).
func Ranking(scores []Score, catalogOrder []string) []Score {
	pos := map[string]int{}
	for i, id := range catalogOrder {
		pos[id] = i
	}
	out := slices.Clone(scores)
	slices.SortStableFunc(out, func(a, b Score) int {
		return cmp.Or(
			cmp.Compare(b.Opened, a.Opened),
			cmp.Compare(a.Failed, b.Failed),
			b.LastOK.Compare(a.LastOK),
			cmp.Compare(rank(pos, a.Strategy), rank(pos, b.Strategy)),
		)
	})
	return out
}

func rank(pos map[string]int, id string) int {
	if p, ok := pos[id]; ok {
		return p
	}
	return len(pos)
}

// Rotation — стратегии для ротации на живом трафике: до k лучших, открывших
// хотя бы один маркер.
func Rotation(ranked []Score, k int) []string {
	var out []string
	for _, s := range ranked {
		if len(out) == k {
			break
		}
		if s.Opened > 0 {
			out = append(out, s.Strategy)
		}
	}
	return out
}
