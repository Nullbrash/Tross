package dns

import (
	"slices"
	"time"

	"tross/core/lists"
	"tross/core/model"
)

// SetSpec — множество ядра и домены (с поддоменами), чьи адреса в него
// попадают: правила пользователя, части профилей сервисов.
type SetSpec struct {
	Name    string
	Domains []string
}

// SetIndex — домен → множества. Неизменяем после создания.
type SetIndex struct{ x lists.Index[string] }

func NewSetIndex(specs []SetSpec) *SetIndex {
	s := &SetIndex{}
	for _, sp := range specs {
		for _, d := range sp.Domains {
			s.x.Add(d, model.MatchSuffix, sp.Name)
		}
	}
	return s
}

// Sets — множества домена, без повторов, в порядке добавления.
func (s *SetIndex) Sets(domain string) []string {
	var out []string
	s.x.Match(domain, func(_ string, _ model.MatchKind, n string) {
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	})
	return out
}

// ClassSet — множество ядра для доменов класса из списка слоя; "" — у слоя
// такого множества нет.
type ClassSet func(layer model.RuleLayer, class model.TrafficClass) string

// Targets — что резолвер делает с адресами ответа.
type Targets struct {
	Sets    []string
	Timeout time.Duration
	// Bypass — кандидат на обход; методы (множества zapret и прокси) —
	// этапы 5–6, пока — только для объяснения.
	Bypass bool
	// Never — встроенный или ручной «никогда не трогать» перекрыл обход.
	Never bool
	// Inside — доступно только изнутри России (не через зарубежный выход).
	Inside bool
}

// Decide — по множествам правил и спискам. rules — Rules.Match(domain)
// (важнейшее первым): из каждого вида берётся первое правило.
func Decide(domain string, ttl time.Duration, ix *SetIndex, rules []model.DomainRule, classSet ClassSet, ttlMin, ttlMax time.Duration) Targets {
	t := Targets{Sets: ix.Sets(domain), Timeout: SetTimeout(ttl, ttlMin, ttlMax)}
	classDone, bypassDone := false, false
	for _, r := range rules {
		switch {
		case !classDone && (r.Purpose == model.PurposeClass || r.Purpose == "" && r.Class != ""):
			classDone = true
			if n := classSet(r.Layer, r.Class); n != "" && !slices.Contains(t.Sets, n) {
				t.Sets = append(t.Sets, n)
			}
		case !bypassDone && (r.Purpose == model.PurposeBypass || r.Purpose == model.PurposeNever):
			bypassDone = true
			t.Bypass, t.Never = r.Purpose == model.PurposeBypass, r.Purpose == model.PurposeNever
		case r.Purpose == model.PurposeInside:
			t.Inside = true
		}
	}
	return t
}

// SetTimeout — срок адреса в множестве: TTL ответа в пределах. Короче нижнего
// предела нельзя: адрес исчез бы из множества посреди долгого соединения
// раньше, чем клиент снова спросит имя.
func SetTimeout(ttl, lo, hi time.Duration) time.Duration {
	return min(max(ttl, lo), hi)
}
