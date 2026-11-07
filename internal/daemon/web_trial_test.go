package daemon

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tross/internal/config"
	"tross/internal/store"
)

func trialSettings(t *testing.T) (*settingsAPI, *store.SQLite, context.Context) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tross.yaml")
	if err := os.WriteFile(path, []byte(strings.ReplaceAll(testConfig, "%PORT%", "12345")), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open("", store.DefaultRetention())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	active, err := config.FileSections(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &settingsAPI{path: path, st: st, active: active, lifetime: ctx, prepare: func(*config.Config) {}}, st, ctx
}

func TestSettingsTrialRollsBackAndRestoresOverlay(t *testing.T) {
	s, st, ctx := trialSettings(t)
	var applied []*config.Config
	s.apply = func(_ context.Context, cfg *config.Config) error {
		applied = append(applied, cfg)
		return nil
	}
	if _, err := st.SaveOverlay(ctx, 0, []byte(`{"links":{"isp1":{"priority":99}}}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartTrial(ctx); err != nil {
		t.Fatal(err)
	}
	if len(applied) != 1 || applied[0].Links[0].Priority != 99 {
		t.Fatalf("candidate was not applied: %#v", applied)
	}
	trial, err := st.ConfigTrial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	trial.Expires = time.Now().Add(-time.Second)
	if err := st.SaveConfigTrial(ctx, trial); err != nil {
		t.Fatal(err)
	}
	if err := s.rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if len(applied) != 2 || applied[1].Links[0].Priority == 99 {
		t.Fatalf("previous configuration was not restored: %#v", applied)
	}
	if trial, err := st.ConfigTrial(ctx); err != nil || len(trial.Candidate) != 0 {
		t.Fatalf("trial remains after rollback: %#v %v", trial, err)
	}
	o, err := st.Overlay(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(o.Data) != string(s.active) {
		t.Fatalf("overlay differs from restored active config: %s vs %s", o.Data, s.active)
	}
}

func TestRecoverConfigTrialRestoresPreviousOverlay(t *testing.T) {
	s, st, ctx := trialSettings(t)
	if _, err := st.SaveOverlay(ctx, 0, []byte(`{"links":{"isp1":{"priority":99}}}`)); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveConfigTrial(ctx, store.ConfigTrial{Previous: s.active, Candidate: []byte(`{"links":{"isp1":{"priority":99}}}`), Expires: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := recoverConfigTrial(ctx, st, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}
	o, err := st.Overlay(ctx)
	if err != nil || string(o.Data) != string(s.active) {
		t.Fatalf("recovery overlay: %s %v", o.Data, err)
	}
}
