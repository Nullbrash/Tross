package config

import (
	"context"
	"testing"
	"time"

	"tross/internal/store"
)

func TestTrialManagerRecoversUnconfirmed(t *testing.T) {
	s, err := store.Open("", store.DefaultRetention()); if err != nil { t.Fatal(err) }; defer s.Close()
	now := time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)
	m := TrialManager{Store:s, Now:func() time.Time{return now}}
	if _, err := m.Begin(context.Background(), []byte(`{"old":1}`), []byte(`{"new":1}`), 90*time.Second); err != nil { t.Fatal(err) }
	got, err := m.Recover(context.Background()); if err != nil || string(got) != `{"old":1}` { t.Fatalf("%s %v", got, err) }
}

func TestTrialManagerKeepsConfirmed(t *testing.T) {
	s, err := store.Open("", store.DefaultRetention()); if err != nil { t.Fatal(err) }; defer s.Close()
	m := TrialManager{Store:s}
	if _, err := m.Begin(context.Background(), []byte(`old`), []byte(`new`), time.Minute); err != nil { t.Fatal(err) }
	if err := m.Confirm(context.Background()); err != nil { t.Fatal(err) }
	got, err := m.Recover(context.Background()); if err != nil || string(got) != "new" { t.Fatalf("%s %v", got, err) }
}
