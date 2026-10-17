package lists

import (
	"errors"
	"fmt"
	"slices"
	"sync"

	"tross/core/model"
)

// Rules — правила всех слоёв в памяти. Потокобезопасен: резолвер читает на
// каждый запрос, загрузчик и API меняют редко — слой заменяется целиком.
type Rules struct {
	mu      sync.RWMutex
	manual  *Index[model.DomainRule]
	builtin *Index[model.DomainRule]
	learned map[ruleKey]model.DomainRule
	learnIx *Index[model.DomainRule]
	// online — по источнику; значение — общий для источника шаблон (вид,
	// класс, источник): шаблон домена — ключ индекса. Своя копия правила на
	// каждый домен стоила ~290 байт — 1,4 млн доменов списка «заблокировано
	// всё» заняли бы ~400 МБ.
	online map[string]*Index[*model.DomainRule]
}

type ruleKey struct {
	pattern string
	match   model.MatchKind
}

func NewRules() *Rules {
	return &Rules{
		manual: &Index[model.DomainRule]{}, builtin: &Index[model.DomainRule]{},
		learned: map[ruleKey]model.DomainRule{}, learnIx: &Index[model.DomainRule]{},
		online: map[string]*Index[*model.DomainRule]{},
	}
}

func build(rules []model.DomainRule, layer model.RuleLayer) (*Index[model.DomainRule], error) {
	x := &Index[model.DomainRule]{}
	var errs []error
	for i, r := range rules {
		r.Layer = layer
		if err := r.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("rule %d (%s): %w", i, r.Pattern, err))
			continue
		}
		x.Add(r.Pattern, r.Match, r)
	}
	return x, errors.Join(errs...)
}

// SetManual заменяет ручные правила; неверные отбрасываются, ошибка
// перечисляет их, остальные действуют.
func (r *Rules) SetManual(rules []model.DomainRule) error {
	x, err := build(rules, model.LayerManual)
	r.mu.Lock()
	r.manual = x
	r.mu.Unlock()
	return err
}

// SetBuiltin заменяет встроенный слой.
func (r *Rules) SetBuiltin(rules []model.DomainRule) error {
	x, err := build(rules, model.LayerBuiltin)
	r.mu.Lock()
	r.builtin = x
	r.mu.Unlock()
	return err
}

// SetOnline заменяет правила одного онлайн-источника; nil — убрать источник.
func (r *Rules) SetOnline(source string, rules []model.DomainRule) error {
	if rules == nil {
		r.mu.Lock()
		delete(r.online, source)
		r.mu.Unlock()
		return nil
	}
	x := &Index[*model.DomainRule]{}
	var errs []error
	// Шаблоны по (назначение, класс, метод): у онлайн-источника они общие.
	templates := map[model.DomainRule]*model.DomainRule{}
	for i, rule := range rules {
		rule.Layer, rule.Source = model.LayerOnline, source
		if err := rule.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("rule %d (%s): %w", i, rule.Pattern, err))
			continue
		}
		key := rule
		key.Pattern, key.Match = "", ""
		t := templates[key]
		if t == nil {
			t = &key
			templates[key] = t
		}
		x.Add(rule.Pattern, rule.Match, t)
	}
	r.mu.Lock()
	r.online[source] = x
	r.mu.Unlock()
	return errors.Join(errs...)
}

// Learn добавляет или заменяет выученное правило (тот же шаблон и способ
// сопоставления).
func (r *Rules) Learn(rule model.DomainRule) error {
	rule.Layer = model.LayerLearned
	if err := rule.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.learned[ruleKey{rule.Pattern, rule.Match}] = rule
	// Выученных — единицы и десятки, индекс пересобирается целиком.
	x := &Index[model.DomainRule]{}
	for _, l := range r.learned {
		x.Add(l.Pattern, l.Match, l)
	}
	r.learnIx = x
	return nil
}

// Match — все подходящие правила, самое важное первым (model.DomainRule.Precedes).
func (r *Rules) Match(domain string) []model.DomainRule {
	var out []model.DomainRule
	add := func(_ string, _ model.MatchKind, v model.DomainRule) { out = append(out, v) }
	r.mu.RLock()
	r.manual.Match(domain, add)
	r.learnIx.Match(domain, add)
	r.builtin.Match(domain, add)
	for _, x := range r.online {
		x.Match(domain, func(p string, k model.MatchKind, t *model.DomainRule) {
			rule := *t
			rule.Pattern, rule.Match = p, k
			out = append(out, rule)
		})
	}
	r.mu.RUnlock()
	slices.SortStableFunc(out, func(a, b model.DomainRule) int {
		switch {
		case a.Precedes(b):
			return -1
		case b.Precedes(a):
			return 1
		}
		return 0
	})
	return out
}

// Lookup — самое важное подходящее правило.
func (r *Rules) Lookup(domain string) (model.DomainRule, bool) {
	m := r.Match(domain)
	if len(m) == 0 {
		return model.DomainRule{}, false
	}
	return m[0], true
}

// Counts — число правил по слоям (онлайн — по источникам).
func (r *Rules) Counts() (manual, learned, builtin int, online map[string]int) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	online = make(map[string]int, len(r.online))
	for s, x := range r.online {
		online[s] = x.Len()
	}
	return r.manual.Len(), len(r.learned), r.builtin.Len(), online
}
