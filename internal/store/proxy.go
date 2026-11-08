package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"tross/core/proxypolicy"
)

var ErrNoDraft = errors.New("store: no such policy draft")

// PolicyAudit — запись о создании, применении, истечении или отклонении
// правила. Содержит область правила, но никогда не ключ proxy или URL.
type PolicyAudit struct {
	At    time.Time
	Topic string
	Data  json.RawMessage
}

// PolicyStore — постоянные данные фазы 1. Исполнитель политики и API будут
// добавлены следующими фазами; интерфейс не даёт им скрытого права применения.
type PolicyStore interface {
	SavePolicyListVersion(context.Context, proxypolicy.ListVersion) error
	PolicyListVersions(context.Context) ([]proxypolicy.ListVersion, error)
	SavePolicyException(context.Context, proxypolicy.TemporaryException) error
	PolicyExceptions(context.Context, time.Time) ([]proxypolicy.TemporaryException, error)
	SavePolicyDraft(context.Context, proxypolicy.Draft) error
	PolicyDraft(context.Context, string, time.Time) (proxypolicy.Draft, error)
	ConsumePolicyDraft(context.Context, string, time.Time) error
	AppendPolicyAudit(context.Context, PolicyAudit) error
	PolicyAudit(context.Context, time.Time, int) ([]PolicyAudit, error)
}

var _ PolicyStore = (*SQLite)(nil)

func (s *SQLite) SavePolicyListVersion(ctx context.Context, v proxypolicy.ListVersion) error {
	if err := s.check(); err != nil {
		return err
	}
	if err := v.Validate(); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO policy_list_versions (source, version, sha256, checked) VALUES (?, ?, ?, ?)
		ON CONFLICT (source) DO UPDATE SET version=excluded.version, sha256=excluded.sha256, checked=excluded.checked`, v.Source, v.Version, v.SHA256, v.CheckedAt.UnixMilli())
	return err
}

func (s *SQLite) PolicyListVersions(ctx context.Context) ([]proxypolicy.ListVersion, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT source, version, sha256, checked FROM policy_list_versions ORDER BY source`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []proxypolicy.ListVersion
	for rows.Next() {
		var v proxypolicy.ListVersion
		var checked int64
		if err := rows.Scan(&v.Source, &v.Version, &v.SHA256, &checked); err != nil {
			return nil, err
		}
		v.CheckedAt = time.UnixMilli(checked)
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *SQLite) SavePolicyException(ctx context.Context, e proxypolicy.TemporaryException) error {
	if err := s.check(); err != nil {
		return err
	}
	if err := e.Validate(); err != nil {
		return err
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO policy_exceptions (id, data, created, expires) VALUES (?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET data=excluded.data, created=excluded.created, expires=excluded.expires`, e.ID, b, e.CreatedAt.UnixMilli(), e.ExpiresAt.UnixMilli())
	return err
}

func (s *SQLite) PolicyExceptions(ctx context.Context, now time.Time) ([]proxypolicy.TemporaryException, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT data FROM policy_exceptions WHERE expires > ? ORDER BY expires, id`, now.UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []proxypolicy.TemporaryException
	for rows.Next() {
		var e proxypolicy.TemporaryException
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, &e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *SQLite) SavePolicyDraft(ctx context.Context, d proxypolicy.Draft) error {
	if err := s.check(); err != nil {
		return err
	}
	if err := d.Validate(time.Now()); err != nil {
		return err
	}
	b, err := json.Marshal(d)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO policy_drafts (token, data, expires, used) VALUES (?, ?, ?, 0)`, d.Token, b, d.ExpiresAt.UnixMilli())
	return err
}

func (s *SQLite) PolicyDraft(ctx context.Context, token string, now time.Time) (proxypolicy.Draft, error) {
	if err := s.check(); err != nil {
		return proxypolicy.Draft{}, err
	}
	var b []byte
	var expires int64
	var used int
	err := s.db.QueryRowContext(ctx, `SELECT data, expires, used FROM policy_drafts WHERE token = ?`, token).Scan(&b, &expires, &used)
	if errors.Is(err, sql.ErrNoRows) || err == nil && (used != 0 || now.UnixMilli() >= expires) {
		return proxypolicy.Draft{}, ErrNoDraft
	}
	if err != nil {
		return proxypolicy.Draft{}, err
	}
	var d proxypolicy.Draft
	if err := json.Unmarshal(b, &d); err != nil {
		return proxypolicy.Draft{}, err
	}
	return d, nil
}

// ConsumePolicyDraft помечает ссылку использованной. Применения правила здесь
// нет: его добавит только подтверждённый API фазы 4 в общей транзакции.
func (s *SQLite) ConsumePolicyDraft(ctx context.Context, token string, now time.Time) error {
	if err := s.check(); err != nil {
		return err
	}
	r, err := s.db.ExecContext(ctx, `UPDATE policy_drafts SET used = 1 WHERE token = ? AND used = 0 AND expires > ?`, token, now.UnixMilli())
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrNoDraft
	}
	return nil
}

func (s *SQLite) AppendPolicyAudit(ctx context.Context, a PolicyAudit) error {
	if err := s.check(); err != nil {
		return err
	}
	if a.At.IsZero() || a.Topic == "" || !json.Valid(a.Data) {
		return errors.New("store: invalid policy audit")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO policy_audit (at, topic, data) VALUES (?, ?, ?)`, a.At.UnixMilli(), a.Topic, []byte(a.Data))
	return err
}

func (s *SQLite) PolicyAudit(ctx context.Context, since time.Time, limit int) ([]PolicyAudit, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 1000
	}
	rows, err := s.db.QueryContext(ctx, `SELECT at, topic, data FROM policy_audit WHERE at >= ? ORDER BY at, id LIMIT ?`, since.UnixMilli(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PolicyAudit
	for rows.Next() {
		var a PolicyAudit
		var at int64
		if err := rows.Scan(&at, &a.Topic, &a.Data); err != nil {
			return nil, err
		}
		a.At = time.UnixMilli(at)
		out = append(out, a)
	}
	return out, rows.Err()
}
