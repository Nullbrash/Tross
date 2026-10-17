package dns

import (
	"container/list"
	"net/netip"
	"sync"
	"time"
)

// Key — имя (нормализованное), тип запроса и просьба о подписях DNSSEC (ответ
// с ними и без — разный).
type Key struct {
	Name string
	Type uint16
	DO   bool
}

// Entry — ответ в кэше.
type Entry struct {
	// Msg — ответ как пришёл от сервера; TTL при выдаче правит резолвер.
	Msg []byte
	// Addrs — адреса ответа (для множеств ядра); пусто — отрицательный ответ.
	Addrs  []netip.Addr
	TTL    time.Duration
	Stored time.Time
}

type State int

const (
	Miss State = iota
	Fresh
	// Stale — срок вышел, но ответ ещё отдаётся, пока идёт обновление: имя
	// открывается сразу, а не после похода к серверу (RFC 8767).
	Stale
)

// Hit — результат Get.
type Hit struct {
	Entry
	State State
	// Left — сколько ещё жить свежему ответу.
	Left time.Duration
	// Refresh — резолверу обновить ответ в фоне (устарел или популярный
	// ответ скоро истечёт); выдаётся одному запросу, до Put или Abort.
	Refresh bool
}

type CacheParams struct {
	Size int
	// StaleFor — сколько после срока ответ ещё можно отдать.
	StaleFor time.Duration
	// PrefetchHits — с этого числа обращений имя считается популярным и
	// обновляется до истечения, когда осталось PrefetchLeft его срока.
	PrefetchHits int
	PrefetchLeft float64
}

func DefaultCacheParams(size int) CacheParams {
	return CacheParams{Size: size, StaleFor: time.Hour, PrefetchHits: 3, PrefetchLeft: 0.1}
}

// Cache — LRU с отдачей устаревшего и упреждающим обновлением.
// Потокобезопасен.
type Cache struct {
	mu sync.Mutex
	p  CacheParams
	ll *list.List
	m  map[Key]*list.Element
}

type cached struct {
	key        Key
	e          Entry
	hits       int
	refreshing bool
}

func NewCache(p CacheParams) *Cache {
	return &Cache{p: p, ll: list.New(), m: map[Key]*list.Element{}}
}

func (c *Cache) Get(k Key, now time.Time) Hit {
	c.mu.Lock()
	defer c.mu.Unlock()
	el := c.m[k]
	if el == nil {
		return Hit{}
	}
	v := el.Value.(*cached)
	age := now.Sub(v.e.Stored)
	switch {
	case age < v.e.TTL:
		c.ll.MoveToFront(el)
		v.hits++
		h := Hit{Entry: v.e, State: Fresh, Left: v.e.TTL - age}
		if !v.refreshing && v.hits >= c.p.PrefetchHits && float64(h.Left) <= float64(v.e.TTL)*c.p.PrefetchLeft {
			v.refreshing, h.Refresh = true, true
		}
		return h
	case age < v.e.TTL+c.p.StaleFor:
		c.ll.MoveToFront(el)
		h := Hit{Entry: v.e, State: Stale, Refresh: !v.refreshing}
		v.refreshing = true
		return h
	}
	c.ll.Remove(el)
	delete(c.m, k)
	return Hit{}
}

// Put — новый ответ; обращения к имени сохраняются (популярность).
func (c *Cache) Put(k Key, e Entry) {
	if c.p.Size <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el := c.m[k]; el != nil {
		v := el.Value.(*cached)
		v.e, v.refreshing = e, false
		c.ll.MoveToFront(el)
		return
	}
	c.m[k] = c.ll.PushFront(&cached{key: k, e: e})
	for c.ll.Len() > c.p.Size {
		old := c.ll.Back()
		c.ll.Remove(old)
		delete(c.m, old.Value.(*cached).key)
	}
}

// Abort — фоновое обновление не удалось: следующий запрос попробует снова.
func (c *Cache) Abort(k Key) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el := c.m[k]; el != nil {
		el.Value.(*cached).refreshing = false
	}
}

func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}
