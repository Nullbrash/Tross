package config

import (
	"context"
	"errors"
	"time"

	"tross/internal/store"
)

var ErrNoTrial = errors.New("config: no active trial")

// TrialManager хранит предыдущий набор до явного подтверждения новой
// конфигурации. Применение выполняет вызывающий код, чтобы не смешивать
// журнал транзакции с Linux-плоскостью данных.
type TrialManager struct {
	Store store.AuthStore
	Now   func() time.Time
}

func (m TrialManager) now() time.Time {
	if m.Now != nil { return m.Now() }
	return time.Now()
}

func (m TrialManager) Begin(ctx context.Context, previous, candidate []byte, keep time.Duration) (store.ConfigTrial, error) {
	t := store.ConfigTrial{Previous: previous, Candidate: candidate, Expires: m.now().Add(keep)}
	return t, m.Store.SaveConfigTrial(ctx, t)
}

func (m TrialManager) Confirm(ctx context.Context) error {
	t, err := m.Store.ConfigTrial(ctx)
	if err != nil { return err }
	if len(t.Candidate) == 0 { return ErrNoTrial }
	if !m.now().Before(t.Expires) { return m.Store.DeleteConfigTrial(ctx) }
	t.Confirmed = true
	return m.Store.SaveConfigTrial(ctx, t)
}

// Recover возвращает документ, который обязан стать действующим после
// перезапуска: подтверждённый кандидат либо предыдущий набор.
func (m TrialManager) Recover(ctx context.Context) ([]byte, error) {
	t, err := m.Store.ConfigTrial(ctx)
	if err != nil || len(t.Candidate) == 0 { return nil, err }
	if t.Confirmed { err = m.Store.DeleteConfigTrial(ctx); return t.Candidate, err }
	err = m.Store.DeleteConfigTrial(ctx)
	return t.Previous, err
}
