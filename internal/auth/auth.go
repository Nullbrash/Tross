// Package auth — вход в интерфейс: пароль (argon2id), сессии с токеном
// против подделки запросов (CSRF), ограничение попыток. Пароль задаётся
// только командой root на самом мини-ПК, не по сети.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"

	"tross/internal/store"
)

// Параметры argon2id: ~50 мс на ноутбуке-стенде — перебор по сети
// бесполезен, вход не тормозит.
const (
	argonTime    = 1
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
	saltLen      = 16
)

var (
	ErrNoPassword = errors.New("auth: password is not set: run `trossd passwd` on the box")
	ErrBadLogin   = errors.New("auth: wrong password")
	// ErrTooMany — слишком много неудачных попыток с этого адреса.
	ErrTooMany   = errors.New("auth: too many attempts, wait a minute")
	ErrNoSession = errors.New("auth: not logged in")
	ErrShort     = errors.New("auth: password must be at least 10 characters")
)

// HashPassword — строка вида $argon2id$v=19$m=…,t=…,p=…$соль$хэш.
func HashPassword(pw string) (string, error) {
	if len([]rune(pw)) < 10 {
		return "", ErrShort
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	enc := base64.RawStdEncoding.EncodeToString
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads, enc(salt), enc(key)), nil
}

// CheckPassword — сравнение за постоянное время.
func CheckPassword(hash, pw string) bool {
	p := strings.Split(hash, "$")
	if len(p) != 6 || p[1] != "argon2id" {
		return false
	}
	var m, t uint32
	var th uint8
	if _, err := fmt.Sscanf(p[3], "m=%d,t=%d,p=%d", &m, &t, &th); err != nil {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(p[4])
	want, err2 := base64.RawStdEncoding.DecodeString(p[5])
	if err1 != nil || err2 != nil || len(want) == 0 {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, th, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

const (
	// SessionTTL — сессия живёт месяц, если ею пользуются; IdleTTL —
	// неделя без входа закрывает её.
	SessionTTL = 30 * 24 * time.Hour
	IdleTTL    = 7 * 24 * time.Hour
	// touchEvery — «последний раз» в базу не чаще (беречь SSD).
	touchEvery = time.Minute
	// Неудачные попытки: с одного адреса — 5 за минуту, всего — 30.
	failWindow  = time.Minute
	failPerAddr = 5
	failTotal   = 30
	// checkWait — сколько попытка ждёт очереди на проверку пароля.
	checkWait = 10 * time.Second
)

// Session — проверенная сессия.
type Session struct {
	CSRF    string
	Expires time.Time
	hash    []byte
}

// Service — вход и сессии.
type Service struct {
	st  store.AuthStore
	now func() time.Time

	mu    sync.Mutex
	fails map[string][]time.Time
	all   []time.Time

	// Проверка пароля берёт 64 МБ (argon2id): по одной за раз, иначе
	// поток одновременных входов из LAN съест память мини-ПК.
	checking chan struct{}
	check    func(hash, pw string) bool
}

func New(st store.AuthStore) *Service {
	return &Service{st: st, now: time.Now, fails: map[string][]time.Time{},
		checking: make(chan struct{}, 1), check: CheckPassword}
}

func token() (string, []byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	t := base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(t))
	return t, h[:], nil
}

func hashOf(t string) []byte {
	h := sha256.Sum256([]byte(t))
	return h[:]
}

// allowLocked — можно ли сейчас пробовать с адреса.
func (s *Service) allowLocked(addr string, now time.Time) bool {
	keep := func(ts []time.Time) []time.Time {
		out := ts[:0]
		for _, t := range ts {
			if now.Sub(t) < failWindow {
				out = append(out, t)
			}
		}
		return out
	}
	s.all = keep(s.all)
	s.fails[addr] = keep(s.fails[addr])
	if len(s.fails[addr]) == 0 {
		delete(s.fails, addr)
	}
	return len(s.fails[addr]) < failPerAddr && len(s.all) < failTotal
}

// Login — проверка пароля; удачно — новая сессия (токен для cookie).
// Попытка засчитывается как неудача до проверки и снимается только при
// успехе: одновременные запросы не проходят лимит все разом.
func (s *Service) Login(ctx context.Context, pw, addr, agent string) (string, Session, error) {
	now := s.now()
	s.mu.Lock()
	ok := s.allowLocked(addr, now)
	if ok {
		s.fails[addr] = append(s.fails[addr], now)
		s.all = append(s.all, now)
	}
	s.mu.Unlock()
	if !ok {
		return "", Session{}, ErrTooMany
	}
	hash, err := s.st.PasswordHash(ctx)
	if err == nil && hash == "" {
		err = ErrNoPassword
	}
	var good bool
	if err == nil {
		good, err = s.checkOne(ctx, hash, pw)
	}
	if err != nil {
		s.unreserve(addr, now)
		return "", Session{}, err
	}
	if !good {
		return "", Session{}, ErrBadLogin
	}
	s.unreserve(addr, now)
	return s.Open(ctx, addr, agent)
}

// checkOne — проверка пароля в очереди по одной; не дождался — ErrTooMany.
func (s *Service) checkOne(ctx context.Context, hash, pw string) (bool, error) {
	t := time.NewTimer(checkWait)
	defer t.Stop()
	select {
	case s.checking <- struct{}{}:
	case <-ctx.Done():
		return false, ctx.Err()
	case <-t.C:
		return false, ErrTooMany
	}
	defer func() { <-s.checking }()
	return s.check(hash, pw), nil
}

// unreserve снимает засчитанную заранее попытку (успех или проверки не было).
func (s *Service) unreserve(addr string, at time.Time) {
	drop := func(ts []time.Time) []time.Time {
		for i := len(ts) - 1; i >= 0; i-- {
			if ts[i].Equal(at) {
				return append(ts[:i], ts[i+1:]...)
			}
		}
		return ts
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.all = drop(s.all)
	if f := drop(s.fails[addr]); len(f) > 0 {
		s.fails[addr] = f
	} else {
		delete(s.fails, addr)
	}
}

// Open — новая сессия без пароля (после ключа доступа).
func (s *Service) Open(ctx context.Context, addr, agent string) (string, Session, error) {
	tok, h, err := token()
	if err != nil {
		return "", Session{}, err
	}
	csrf, _, err := token()
	if err != nil {
		return "", Session{}, err
	}
	if len(agent) > 200 {
		agent = agent[:200]
	}
	now := s.now()
	x := store.Session{TokenHash: h, CSRF: csrf, Created: now, Last: now, Expires: now.Add(SessionTTL), Addr: addr, Agent: agent}
	if err := s.st.SaveSession(ctx, x); err != nil {
		return "", Session{}, err
	}
	return tok, Session{CSRF: csrf, Expires: x.Expires, hash: h}, nil
}

// Check — сессия по токену из cookie; продлевает «последний раз».
func (s *Service) Check(ctx context.Context, tok, addr string) (Session, error) {
	if tok == "" {
		return Session{}, ErrNoSession
	}
	h := hashOf(tok)
	x, err := s.st.SessionByHash(ctx, h)
	if errors.Is(err, store.ErrNoSession) {
		return Session{}, ErrNoSession
	}
	if err != nil {
		return Session{}, err
	}
	now := s.now()
	if now.After(x.Expires) || now.Sub(x.Last) > IdleTTL {
		_ = s.st.DeleteSession(ctx, h)
		return Session{}, ErrNoSession
	}
	if now.Sub(x.Last) >= touchEvery {
		x.Last, x.Addr = now, addr
		_ = s.st.SaveSession(ctx, x)
	}
	return Session{CSRF: x.CSRF, Expires: x.Expires, hash: h}, nil
}

func (s *Service) Logout(ctx context.Context, tok string) error {
	return s.st.DeleteSession(ctx, hashOf(tok))
}

// CheckCSRF — токен из заголовка запроса совпадает с токеном сессии.
func CheckCSRF(x Session, header string) bool {
	return header != "" && subtle.ConstantTimeCompare([]byte(header), []byte(x.CSRF)) == 1
}

// HasPassword — пароль задан (иначе интерфейс показывает, как его задать).
func (s *Service) HasPassword(ctx context.Context) (bool, error) {
	h, err := s.st.PasswordHash(ctx)
	return h != "", err
}

// SetPassword — смена пароля (закрывает все сессии).
func SetPassword(ctx context.Context, st store.AuthStore, pw string) error {
	h, err := HashPassword(pw)
	if err != nil {
		return err
	}
	return st.SetPasswordHash(ctx, h)
}
