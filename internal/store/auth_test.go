package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAuthStore(t *testing.T) {
	ctx := context.Background()
	s := openMem(t)
	if h, err := s.PasswordHash(ctx); err != nil || h != "" {
		t.Fatalf("no password yet: %q %v", h, err)
	}
	now := time.Now().Truncate(time.Millisecond)
	sess := Session{TokenHash: []byte{1, 2, 3}, CSRF: "c", Created: now, Last: now, Expires: now.Add(time.Hour), Addr: "192.168.10.20", Agent: "phone"}
	if err := s.SaveSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	got, err := s.SessionByHash(ctx, sess.TokenHash)
	if err != nil || got.CSRF != "c" || !got.Expires.Equal(sess.Expires) || got.Agent != "phone" {
		t.Fatalf("session %+v %v", got, err)
	}
	// Новый пароль закрывает все сессии.
	if err := s.SetPasswordHash(ctx, "h1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionByHash(ctx, sess.TokenHash); !errors.Is(err, ErrNoSession) {
		t.Errorf("session survived a password change: %v", err)
	}
	if h, _ := s.PasswordHash(ctx); h != "h1" {
		t.Errorf("hash %q", h)
	}
	sess.Expires = now.Add(-time.Minute)
	_ = s.SaveSession(ctx, sess)
	_ = s.PruneSessions(ctx, now)
	if _, err := s.SessionByHash(ctx, sess.TokenHash); !errors.Is(err, ErrNoSession) {
		t.Errorf("expired session kept: %v", err)
	}

	pk := Passkey{ID: []byte("k1"), Name: "phone", Data: []byte("{}"), Created: now}
	if err := s.SavePasskey(ctx, pk); err != nil {
		t.Fatal(err)
	}
	pk.Last = now.Add(time.Minute)
	_ = s.SavePasskey(ctx, pk)
	ps, _ := s.Passkeys(ctx)
	if len(ps) != 1 || !ps[0].Last.Equal(pk.Last) {
		t.Fatalf("passkeys %+v", ps)
	}
	_ = s.DeletePasskey(ctx, pk.ID)
	if ps, _ := s.Passkeys(ctx); len(ps) != 0 {
		t.Error("passkey not deleted")
	}

	o, err := s.Overlay(ctx)
	if err != nil || o.Version != 0 || string(o.Data) != "{}" {
		t.Fatalf("empty overlay %+v %v", o, err)
	}
	o, err = s.SaveOverlay(ctx, 0, []byte(`{"a":1}`))
	if err != nil || o.Version != 1 {
		t.Fatalf("save %+v %v", o, err)
	}
	// Правка поверх устаревшей версии — отказ.
	if _, err := s.SaveOverlay(ctx, 0, []byte(`{"a":2}`)); !errors.Is(err, ErrStale) {
		t.Errorf("stale save: %v", err)
	}
	if o, _ := s.Overlay(ctx); string(o.Data) != `{"a":1}` {
		t.Errorf("overlay %s", o.Data)
	}
}
