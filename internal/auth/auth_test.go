package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tross/internal/store"
)

func newAuth(t *testing.T) (*Service, *store.SQLite) {
	t.Helper()
	st, err := store.Open("", store.DefaultRetention())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return New(st), st
}

func TestPasswordHash(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil || !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=1,p=2$") {
		t.Fatalf("hash %q %v", h, err)
	}
	if !CheckPassword(h, "correct horse battery") || CheckPassword(h, "correct horse batterY") {
		t.Error("check")
	}
	if h2, _ := HashPassword("correct horse battery"); h2 == h {
		t.Error("same salt twice")
	}
	if _, err := HashPassword("short"); !errors.Is(err, ErrShort) {
		t.Errorf("short password: %v", err)
	}
	for _, bad := range []string{"", "$argon2id$", "$bcrypt$x$y$z$w", "$argon2id$v=19$m=x$a$b"} {
		if CheckPassword(bad, "x") {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestLoginSessionsAndLimits(t *testing.T) {
	ctx := context.Background()
	a, st := newAuth(t)
	if _, _, err := a.Login(ctx, "anything-long", "1.1.1.1", ""); !errors.Is(err, ErrNoPassword) {
		t.Fatalf("no password: %v", err)
	}
	if err := SetPassword(ctx, st, "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	tok, sess, err := a.Login(ctx, "correct horse battery", "192.168.10.20", "phone")
	if err != nil || tok == "" || sess.CSRF == "" {
		t.Fatalf("login %v", err)
	}
	got, err := a.Check(ctx, tok, "192.168.10.20")
	if err != nil || got.CSRF != sess.CSRF {
		t.Fatalf("check %+v %v", got, err)
	}
	if !CheckCSRF(got, sess.CSRF) || CheckCSRF(got, "") || CheckCSRF(got, "x") {
		t.Error("csrf")
	}
	if _, err := a.Check(ctx, tok+"x", ""); !errors.Is(err, ErrNoSession) {
		t.Errorf("forged token: %v", err)
	}
	// Простой больше недели — сессия закрыта.
	a.now = func() time.Time { return time.Now().Add(IdleTTL + time.Hour) }
	if _, err := a.Check(ctx, tok, ""); !errors.Is(err, ErrNoSession) {
		t.Errorf("idle session: %v", err)
	}
	a.now = time.Now

	// 5 неудач с адреса — шестая попытка (даже верная) отклоняется.
	for range 5 {
		if _, _, err := a.Login(ctx, "wrong password!!", "192.168.10.66", ""); !errors.Is(err, ErrBadLogin) {
			t.Fatalf("wrong: %v", err)
		}
	}
	if _, _, err := a.Login(ctx, "correct horse battery", "192.168.10.66", ""); !errors.Is(err, ErrTooMany) {
		t.Errorf("limit: %v", err)
	}
	// Другой адрес — можно; через минуту — снова можно.
	if _, _, err := a.Login(ctx, "correct horse battery", "192.168.10.67", ""); err != nil {
		t.Errorf("other address: %v", err)
	}
	a.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if _, _, err := a.Login(ctx, "correct horse battery", "192.168.10.66", ""); err != nil {
		t.Errorf("after a minute: %v", err)
	}
	a.now = time.Now

	// Смена пароля закрывает все сессии; выход — свою.
	tok2, _, _ := a.Login(ctx, "correct horse battery", "192.168.10.20", "")
	if err := a.Logout(ctx, tok2); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Check(ctx, tok2, ""); !errors.Is(err, ErrNoSession) {
		t.Error("logout")
	}
	tok3, _, _ := a.Login(ctx, "correct horse battery", "192.168.10.20", "")
	_ = SetPassword(ctx, st, "another long password")
	if _, err := a.Check(ctx, tok3, ""); !errors.Is(err, ErrNoSession) {
		t.Error("password change kept the session")
	}
}

// Одновременные входы: проверка пароля (64 МБ) — строго по одной, и лимит
// неудач держится, даже если все запросы пришли разом.
func TestConcurrentLogins(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		addr    func(i int) string
		wantBad int
	}{
		{"one address", func(int) string { return "192.168.10.66" }, failPerAddr},
		{"many addresses", func(i int) string { return fmt.Sprintf("192.168.11.%d", i) }, failTotal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, st := newAuth(t)
			if err := SetPassword(ctx, st, "correct horse battery"); err != nil {
				t.Fatal(err)
			}
			var cur, peak atomic.Int32
			a.check = func(string, string) bool {
				n := cur.Add(1)
				for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
				}
				time.Sleep(5 * time.Millisecond)
				cur.Add(-1)
				return false
			}
			const n = 60
			errs := make(chan error, n)
			var wg sync.WaitGroup
			for i := range n {
				wg.Go(func() {
					_, _, err := a.Login(ctx, "wrong password!!", tc.addr(i), "")
					errs <- err
				})
			}
			wg.Wait()
			close(errs)
			bad, many := 0, 0
			for err := range errs {
				switch {
				case errors.Is(err, ErrBadLogin):
					bad++
				case errors.Is(err, ErrTooMany):
					many++
				default:
					t.Errorf("unexpected: %v", err)
				}
			}
			if p := peak.Load(); p != 1 {
				t.Errorf("password checks at once: %d, want 1", p)
			}
			if bad != tc.wantBad || bad+many != n {
				t.Errorf("checked %d, refused %d; want %d checked", bad, many, tc.wantBad)
			}
		})
	}
	// Удачный вход не тратит попытку: 10 верных подряд с одного адреса.
	a, st := newAuth(t)
	if err := SetPassword(ctx, st, "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	for i := range 10 {
		if _, _, err := a.Login(ctx, "correct horse battery", "192.168.10.20", ""); err != nil {
			t.Fatalf("login %d: %v", i, err)
		}
	}
}
