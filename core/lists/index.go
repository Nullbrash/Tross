package lists

import (
	"strings"

	"tross/core/model"
)

// Index — значения по доменным шаблонам: точное имя, имя с поддоменами,
// подстрока. Не потокобезопасен; после наполнения только читается.
//
// Таблицы по полному шаблону, а не дерево меток: поиск идёт по суффиксам
// имени (a.b.c → b.c → c), а память — одна запись на шаблон; в онлайн-списках
// сотни тысяч доменов.
type Index[V any] struct {
	exact, suffix map[string][]V
	keywords      []keyword[V]
	n             int
}

type keyword[V any] struct {
	pattern string
	v       V
}

// Add — шаблон уже нормализован (model.NormalizeDomain; подстрока — в
// нижнем регистре).
func (x *Index[V]) Add(pattern string, kind model.MatchKind, v V) {
	switch kind {
	case model.MatchExact:
		if x.exact == nil {
			x.exact = map[string][]V{}
		}
		x.exact[pattern] = append(x.exact[pattern], v)
	case model.MatchSuffix:
		if x.suffix == nil {
			x.suffix = map[string][]V{}
		}
		x.suffix[pattern] = append(x.suffix[pattern], v)
	case model.MatchKeyword:
		x.keywords = append(x.keywords, keyword[V]{pattern, v})
	default:
		return
	}
	x.n++
}

// Len — число добавленных шаблонов.
func (x *Index[V]) Len() int { return x.n }

// Match вызывает fn для каждого значения, шаблон которого подходит к
// нормализованному домену (шаблон — ключ таблицы: значению хранить его не
// нужно).
func (x *Index[V]) Match(domain string, fn func(pattern string, kind model.MatchKind, v V)) {
	for _, v := range x.exact[domain] {
		fn(domain, model.MatchExact, v)
	}
	if x.suffix != nil {
		for d := domain; ; {
			for _, v := range x.suffix[d] {
				fn(d, model.MatchSuffix, v)
			}
			i := strings.IndexByte(d, '.')
			if i < 0 {
				break
			}
			d = d[i+1:]
		}
	}
	for _, k := range x.keywords {
		if strings.Contains(domain, k.pattern) {
			fn(k.pattern, model.MatchKeyword, k.v)
		}
	}
}
