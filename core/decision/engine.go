package decision

import (
	"errors"
	"fmt"
	"hash/fnv"
	"slices"
	"sync"
	"time"

	"tross/core/model"
)

// Гистерезис выбора «лучшего» канала для новых сессий: прежний лучший
// остаётся, пока новый не лучше заметно — иначе классы прыгали бы между
// почти равными каналами. Задержка — с джиттером (см. EffectiveRTT): 4 и
// 10 мс неотличимы в игре, а частые смены стягивают сессии на один канал.
const (
	rttSwitchRatio = 1.25                  // новый лучше хотя бы на 25 %…
	rttSwitchGain  = 10 * time.Millisecond // …и хотя бы на 10 мс
	speedKeepRatio = 0.8
	// DefaultServiceTTL — срок закрепления «устройство + сервис», если у
	// политики класса нет своего.
	DefaultServiceTTL = time.Hour
)

type pinKind uint8

const (
	pinSession pinKind = iota + 1
	pinDestination
	pinService
)

func (k pinKind) String() string {
	return [...]string{"", "session", "destination", "service"}[k]
}

type pinKey struct {
	kind   pinKind
	device string
	value  string // класс, домен/адрес или сервис
}

type pin struct {
	link    model.LinkID
	expires time.Time
}

// Engine — движок решений «канал + метод» поверх Balance: закрепления,
// гистерезис, детерминированный выбор канала для одного соединения при
// балансировке (тот же расклад даёт ядро по хешу адресов).
type Engine struct {
	mu       sync.Mutex
	policies map[model.TrafficClass]model.Policy
	links    []model.LinkStatus
	pins     map[pinKey]pin
	best     map[model.TrafficClass]model.LinkID
	now      func() time.Time
}

var _ DecisionEngine = (*Engine)(nil)

// NewEngine — now nil — системные часы.
func NewEngine(policies map[model.TrafficClass]model.Policy, now func() time.Time) (*Engine, error) {
	if now == nil {
		now = time.Now
	}
	e := &Engine{pins: map[pinKey]pin{}, best: map[model.TrafficClass]model.LinkID{}, now: now}
	return e, e.SetPolicies(policies)
}

func (e *Engine) SetPolicies(p map[model.TrafficClass]model.Policy) error {
	var errs []error
	if _, ok := p[model.ClassDefault]; !ok {
		errs = append(errs, errors.New("no policy for class default"))
	}
	for c, pol := range p {
		if err := pol.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("class %s: %w", c, err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	e.mu.Lock()
	e.policies = p
	e.mu.Unlock()
	return nil
}

// UpdateLinks — свежее состояние каналов; закрепления за непригодными снимаются.
func (e *Engine) UpdateLinks(status []model.LinkStatus) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.links = slices.Clone(status)
	for k, p := range e.pins {
		if !e.usableLocked(p.link) {
			delete(e.pins, k)
		}
	}
	for c, id := range e.best {
		if !e.usableLocked(id) {
			delete(e.best, c)
		}
	}
}

// Prune удаляет истёкшие закрепления (Decide делает это и сам по ходу).
func (e *Engine) Prune() {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	for k, p := range e.pins {
		if !now.Before(p.expires) {
			delete(e.pins, k)
		}
	}
}

func (e *Engine) Decide(f model.Flow, c model.Classification, rule *model.DomainRule) (model.Decision, error) {
	return e.decide(f, c, rule, true)
}

// Explain — то же решение, что дал бы Decide, но без последствий: закрепления
// не создаются и не продлеваются, выбор «лучшего» канала не сдвигается.
// Вопрос «почему так» не должен менять будущие решения.
func (e *Engine) Explain(f model.Flow, c model.Classification, rule *model.DomainRule) (model.Decision, error) {
	return e.decide(f, c, rule, false)
}

func (e *Engine) decide(f model.Flow, c model.Classification, rule *model.DomainRule, commit bool) (model.Decision, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	pol, ok := e.policies[c.Class]
	note := ""
	if !ok {
		pol, note = e.policies[model.ClassDefault], "no policy for class, default used; "
	}
	d := model.Decision{Class: c.Class}
	var why string
	d.Method, d.ProxyID, why = method(pol, rule)

	primary := candidates(pol, e.links, false)
	allowed := func(id model.LinkID) bool {
		if slices.ContainsFunc(primary, func(l model.LinkStatus) bool { return l.Link.ID == id }) {
			return true
		}
		// Канал из запасных — только пока нет пригодного основного.
		return len(primary) == 0 && slices.ContainsFunc(candidates(pol, e.links, true), func(l model.LinkStatus) bool { return l.Link.ID == id })
	}

	key, ttl := e.pinFor(f, c, pol)
	now := e.now()
	if key.kind != 0 {
		if p, ok := e.pins[key]; ok {
			if now.Before(p.expires) && allowed(p.link) {
				if commit {
					p.expires = now.Add(ttl)
					e.pins[key] = p
				}
				d.Link, d.Sticky, d.ExpiresAt = p.link, true, p.expires
				d.Reason = fmt.Sprintf("%spinned (%s); method: %s", note, key.kind, why)
				return d, nil
			}
			if commit {
				delete(e.pins, key)
			}
		}
	}

	switch {
	case rule != nil && rule.Link != "" && allowed(rule.Link):
		d.Link = rule.Link
		note += "link from domain rule; "
	default:
		shares := Balance(pol, e.links)
		if len(shares) == 0 {
			return model.Decision{}, ErrNoUsableLink
		}
		d.Link = e.pickLocked(f, c.Class, pol, shares, commit)
		if len(primary) == 0 {
			note += "fallback link; "
		}
	}
	if key.kind != 0 {
		if commit {
			e.pins[key] = pin{link: d.Link, expires: now.Add(ttl)}
		}
		d.Sticky, d.ExpiresAt = true, now.Add(ttl)
	}
	d.Reason = fmt.Sprintf("%s%s; method: %s", note, pol.Selector, why)
	return d, nil
}

func (e *Engine) pinFor(f model.Flow, c model.Classification, pol model.Policy) (pinKey, time.Duration) {
	ttl := pol.StickyTTL
	if c.PinService && c.Service != "" {
		if ttl <= 0 {
			ttl = DefaultServiceTTL
		}
		return pinKey{pinService, f.Key(), c.Service}, ttl
	}
	switch pol.Stickiness {
	case model.StickSession:
		return pinKey{pinSession, f.Key(), string(c.Class)}, ttl
	case model.StickDestination:
		dst := f.Dst.Addr().String()
		if n, err := model.NormalizeDomain(f.Domain); err == nil {
			dst = n
		}
		return pinKey{pinDestination, f.Key(), dst}, ttl
	case model.StickService:
		if c.Service != "" {
			return pinKey{pinService, f.Key(), c.Service}, ttl
		}
	}
	return pinKey{}, 0
}

func (e *Engine) pickLocked(f model.Flow, class model.TrafficClass, pol model.Policy, shares []LinkShare, commit bool) model.LinkID {
	if pol.Selector == model.SelectBalanced {
		// Хеш «устройство + адрес назначения»: одно и то же назначение с
		// устройства уходит в один канал, а не скачет по соединениям.
		h := fnv.New64a()
		h.Write([]byte(f.Key()))
		h.Write(f.Dst.Addr().AsSlice())
		total := 0
		for _, s := range shares {
			total += s.Weight
		}
		n := int(h.Sum64() % uint64(total))
		for _, s := range shares {
			if n < s.Weight {
				return s.Link
			}
			n -= s.Weight
		}
		return shares[len(shares)-1].Link
	}
	best := shares[0].Link
	if prev, ok := e.best[class]; ok && prev != best && e.keepPrevLocked(pol, prev, best) {
		best = prev
	}
	if commit {
		e.best[class] = best
	}
	return best
}

func (e *Engine) keepPrevLocked(pol model.Policy, prev, next model.LinkID) bool {
	p, okp := e.statusLocked(prev)
	n, okn := e.statusLocked(next)
	if !okp || !okn || !p.Health.State.Usable() {
		return false
	}
	pool := candidates(pol, e.links, false)
	if len(pool) == 0 {
		pool = candidates(pol, e.links, true)
	}
	if !slices.ContainsFunc(pool, func(l model.LinkStatus) bool { return l.Link.ID == prev }) {
		return false
	}
	switch pol.Selector {
	case model.SelectLowestLatency:
		prevRTT, nextRTT := EffectiveRTT(p.Health), EffectiveRTT(n.Health)
		if prevRTT <= 0 {
			return false
		}
		return float64(prevRTT) <= float64(nextRTT)*rttSwitchRatio || prevRTT-nextRTT < rttSwitchGain
	case model.SelectBestThroughput:
		return float64(p.Health.Throughput.DownBps) >= float64(n.Health.Throughput.DownBps)*speedKeepRatio
	case model.SelectBestUpload:
		return float64(p.Health.Throughput.UpBps) >= float64(n.Health.Throughput.UpBps)*speedKeepRatio
	}
	return false
}

func (e *Engine) statusLocked(id model.LinkID) (model.LinkStatus, bool) {
	i := slices.IndexFunc(e.links, func(l model.LinkStatus) bool { return l.Link.ID == id })
	if i < 0 {
		return model.LinkStatus{}, false
	}
	return e.links[i], true
}

func (e *Engine) usableLocked(id model.LinkID) bool {
	l, ok := e.statusLocked(id)
	return ok && l.Health.State.Usable()
}

// method — метод соединения: политика класса, а при auto — доменное правило;
// прокси — только если класс его разрешает (торренты и игры — никогда).
func method(p model.Policy, r *model.DomainRule) (model.Method, string, string) {
	if p.Method != model.MethodAuto {
		return p.Method, "", "class policy"
	}
	if r == nil || r.Method == "" {
		return model.MethodDirect, "", "no domain rule"
	}
	if r.Method == model.MethodProxy && !p.AllowProxy {
		return model.MethodDirect, "", "class forbids proxy"
	}
	return r.Method, r.ProxyID, "domain rule (" + string(r.Layer) + ")"
}

// ClassPlan — что компилируется в ядро для класса: распределение новых
// сессий (с гистерезисом движка) и каналы, закрепления за которыми
// действуют (пригодные основные, а если таких нет — пригодные запасные).
type ClassPlan struct {
	Class    model.TrafficClass
	Shares   []LinkShare
	Pin      model.Stickiness
	PinTTL   time.Duration
	PinLinks []model.LinkID
}

// Plan — по классу на каждую политику, в порядке имён (стабильно для
// сравнения «изменилось ли»).
func (e *Engine) Plan() []ClassPlan {
	e.mu.Lock()
	defer e.mu.Unlock()
	classes := make([]model.TrafficClass, 0, len(e.policies))
	for c := range e.policies {
		classes = append(classes, c)
	}
	slices.Sort(classes)
	out := make([]ClassPlan, 0, len(classes))
	for _, c := range classes {
		pol := e.policies[c]
		cp := ClassPlan{Class: c, Pin: pol.Stickiness, PinTTL: pol.StickyTTL}
		shares := Balance(pol, e.links)
		if len(shares) == 1 {
			best := shares[0].Link
			if prev, ok := e.best[c]; ok && prev != best && e.keepPrevLocked(pol, prev, best) {
				best = prev
			}
			e.best[c] = best
			shares = []LinkShare{{best, 1}}
		}
		cp.Shares = shares
		pool := candidates(pol, e.links, false)
		if len(pool) == 0 {
			pool = candidates(pol, e.links, true)
		}
		for _, l := range pool {
			cp.PinLinks = append(cp.PinLinks, l.Link.ID)
		}
		out = append(out, cp)
	}
	return out
}

// Equal — планы совпадают (не нужно перестраивать ядро).
func (p ClassPlan) Equal(o ClassPlan) bool {
	return p.Class == o.Class && p.Pin == o.Pin && p.PinTTL == o.PinTTL &&
		slices.Equal(p.Shares, o.Shares) && slices.Equal(p.PinLinks, o.PinLinks)
}
