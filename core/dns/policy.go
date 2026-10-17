// Package dns — платформенно-независимая логика резолвера: к каким внешним
// серверам идёт запрос, здоровье серверов по каналам, гонка ответов, кэш и
// в какие множества ядра попадают адреса ответа. Сетевой ввод-вывод — в
// internal/resolver.
package dns

import (
	"cmp"
	"errors"
	"fmt"
	"hash/fnv"
	"slices"
	"time"

	"golang.org/x/net/publicsuffix"

	"tross/core/lists"
	"tross/core/model"
)

// Pool — набор внешних серверов.
type Pool string

const (
	// PoolProtected — для особо личного: серверы вне России без журналов,
	// домен закреплён за одним сервером (каждый видит только свою долю).
	PoolProtected Pool = "protected"
	// PoolFast — для остального: гонка нескольких быстрейших.
	PoolFast Pool = "fast"
)

func (p Pool) Valid() bool { return p == PoolProtected || p == PoolFast }

// Upstream — внешний сервер (адрес и протокол — у резолвера).
type Upstream struct {
	Name string
	// Pools — в каких наборах сервер основной; пусто — только запасной.
	Pools []Pool
	// Backup — назначенный запасной для доли этого сервера в защищённом
	// наборе: при его отказе доля уходит одному серверу, а не всем.
	Backup string
}

// Params — настройки выбора.
type Params struct {
	// Race — сколько серверов быстрого набора спрашивать разом.
	Race int
	// HedgeAfter — без ответа столько, и закреплённую долю страхует
	// следующий сервер (его увидит ещё один, а не все).
	HedgeAfter time.Duration
	// MaxPending — сервер с таким числом запросов в ожидании пропускается.
	MaxPending int
	// SensitiveFallback — весь защищённый набор с запасными отложен:
	// особо личное временно идёт быстрым набором (иначе — ждёт защищённый:
	// имена не уходят, но и не открываются).
	SensitiveFallback bool
}

func DefaultParams() Params {
	return Params{Race: 2, HedgeAfter: 300 * time.Millisecond, MaxPending: 100}
}

// Policy — выбор серверов для запроса. Неизменяема после создания, кроме
// здоровья (Health потокобезопасен).
type Policy struct {
	ups       map[string]Upstream
	protected []string
	fast      []string
	sensitive lists.Index[struct{}]
	health    *Health
	p         Params
}

// NewPolicy — sensitive — шаблоны «домен с поддоменами» особо личного
// (уже нормализованы).
func NewPolicy(ups []Upstream, sensitive []string, h *Health, p Params) (*Policy, error) {
	pol := &Policy{ups: map[string]Upstream{}, health: h, p: p}
	var errs []error
	for _, u := range ups {
		if _, dup := pol.ups[u.Name]; dup || u.Name == "" {
			errs = append(errs, fmt.Errorf("upstream %q: empty or duplicate name", u.Name))
			continue
		}
		pol.ups[u.Name] = u
		for _, pl := range u.Pools {
			switch pl {
			case PoolProtected:
				pol.protected = append(pol.protected, u.Name)
			case PoolFast:
				pol.fast = append(pol.fast, u.Name)
			default:
				errs = append(errs, fmt.Errorf("upstream %q: unknown pool %q", u.Name, pl))
			}
		}
	}
	for _, u := range ups {
		if u.Backup != "" {
			if _, ok := pol.ups[u.Backup]; !ok || u.Backup == u.Name {
				errs = append(errs, fmt.Errorf("upstream %q: unknown backup %q", u.Name, u.Backup))
			}
		}
	}
	if len(pol.protected) == 0 || len(pol.fast) == 0 {
		errs = append(errs, errors.New("both protected and fast pools need at least one upstream"))
	}
	if p.Race < 1 {
		errs = append(errs, errors.New("race must be at least 1"))
	}
	for _, s := range sensitive {
		pol.sensitive.Add(s, model.MatchSuffix, struct{}{})
	}
	return pol, errors.Join(errs...)
}

func (p *Policy) Params() Params { return p.p }

// Sensitive — домен особо личный (защищённый набор).
func (p *Policy) Sensitive(domain string) bool {
	found := false
	p.sensitive.Match(domain, func(string, model.MatchKind, struct{}) { found = true })
	return found
}

// Plan — к каким серверам идёт запрос.
type Plan struct {
	// Race — спросить всех сразу и взять ответ по правилам Race; иначе —
	// по порядку: следующий — при отказе или через HedgeAfter без ответа.
	Race      bool
	Upstreams []string
	Pool      Pool
	// Fallback — особо личное идёт быстрым набором: защищённый недоступен.
	Fallback bool
}

// Plan — серверы для домена через канал link. Особо личное уходит в быстрый
// набор, только если весь защищённый набор с запасными отложен и это
// разрешено (SensitiveFallback); иначе запрос всё равно идёт к защищённому.
func (p *Policy) Plan(domain string, link model.LinkID, now time.Time) Plan {
	if p.Sensitive(domain) {
		seq, usable := p.pinned(domain, link, now)
		if !usable && p.p.SensitiveFallback {
			return Plan{Race: true, Upstreams: p.race(link, now), Pool: PoolFast, Fallback: true}
		}
		return Plan{Upstreams: seq, Pool: PoolProtected}
	}
	return Plan{Race: true, Upstreams: p.race(link, now), Pool: PoolFast}
}

// pinned — доля по зарегистрированному домену (www.example.com и
// api.example.com — к одному серверу): основной по наибольшему весу
// (rendezvous hashing — отказ одного сервера не перетасовывает доли других),
// затем его запасной, затем остальные по весу. usable=false — все отложены
// (порядок тогда — без учёта здоровья).
func (p *Policy) pinned(domain string, link model.LinkID, now time.Time) (seq []string, usable bool) {
	key, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		key = domain
	}
	order := slices.Clone(p.protected)
	slices.SortStableFunc(order, func(a, b string) int { return cmp.Compare(weight(key, b), weight(key, a)) })
	add := func(n string) {
		if n != "" && !slices.Contains(seq, n) {
			seq = append(seq, n)
		}
	}
	add(order[0])
	add(p.ups[order[0]].Backup)
	for _, n := range order[1:] {
		add(n)
	}
	for _, n := range order[1:] {
		add(p.ups[n].Backup)
	}
	ok := slices.DeleteFunc(slices.Clone(seq), func(n string) bool { return !p.health.Usable(n, link, now, p.p.MaxPending) })
	if len(ok) == 0 {
		return seq, false
	}
	return ok, true
}

// race — быстрейшие по здоровью через этот канал.
func (p *Policy) race(link model.LinkID, now time.Time) []string {
	all := slices.Clone(p.fast)
	slices.SortStableFunc(all, func(a, b string) int {
		return cmp.Compare(p.health.Score(a, link), p.health.Score(b, link))
	})
	usable := slices.DeleteFunc(slices.Clone(all), func(n string) bool { return !p.health.Usable(n, link, now, p.p.MaxPending) })
	if len(usable) == 0 {
		usable = all
	}
	return usable[:min(p.p.Race, len(usable))]
}

func weight(key, server string) uint64 { return Score(key, server) }

// Score — вес пары «ключ + участник» для rendezvous hashing, одинаковый
// между перезапусками. Перемешивание (splitmix64) обязательно: у FNV
// участники, различающиеся последним символом (isp1/isp2, cloudflare-2),
// почти не расходятся в старших битах — один выигрывал бы всегда.
func Score(key, member string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(key))
	h.Write([]byte{0})
	h.Write([]byte(member))
	x := h.Sum64()
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	return x ^ x>>31
}
