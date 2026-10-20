package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Вход в интерфейс и правки интерфейса поверх файла конфигурации.

var (
	ErrNoSession = errors.New("store: no such session")
	// ErrStale — правка интерфейса сделана поверх устаревшей версии.
	ErrStale = errors.New("store: overlay changed since it was read")
)

// Session — сессия входа; хранится хэш токена, не сам токен.
type Session struct {
	TokenHash []byte
	CSRF      string
	Created   time.Time
	Last      time.Time
	Expires   time.Time
	Addr      string
	Agent     string
}

// Passkey — ключ доступа (WebAuthn); Data — сериализованные данные
// библиотеки.
type Passkey struct {
	ID      []byte    `json:"-"`
	Name    string    `json:"name"`
	Data    []byte    `json:"-"`
	Created time.Time `json:"created"`
	Last    time.Time `json:"last,omitzero"`
}

// Overlay — документ правок интерфейса и его версия.
type Overlay struct {
	Version int64
	Data    []byte
	Updated time.Time
}

// AuthStore — хранение входа и правок интерфейса.
type AuthStore interface {
	PasswordHash(ctx context.Context) (string, error)
	// SetPasswordHash заменяет пароль и закрывает все сессии.
	SetPasswordHash(ctx context.Context, hash string) error
	SaveSession(ctx context.Context, s Session) error
	SessionByHash(ctx context.Context, hash []byte) (Session, error)
	DeleteSession(ctx context.Context, hash []byte) error
	// DeleteSessions — все сессии (смена пароля, потеря телефона).
	DeleteSessions(ctx context.Context) error
	PruneSessions(ctx context.Context, now time.Time) error
	SavePasskey(ctx context.Context, p Passkey) error
	Passkeys(ctx context.Context) ([]Passkey, error)
	DeletePasskey(ctx context.Context, id []byte) error
	Overlay(ctx context.Context) (Overlay, error)
	// SaveOverlay — новая версия, если текущая — expect (иначе ErrStale).
	SaveOverlay(ctx context.Context, expect int64, data []byte) (Overlay, error)
}

var _ AuthStore = (*SQLite)(nil)

func (s *SQLite) PasswordHash(ctx context.Context) (string, error) {
	if err := s.check(); err != nil {
		return "", err
	}
	var h string
	err := s.db.QueryRowContext(ctx, `SELECT v FROM auth WHERE k = 'password'`).Scan(&h)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return h, err
}

func (s *SQLite) SetPasswordHash(ctx context.Context, hash string) error {
	if err := s.check(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO auth (k, v) VALUES ('password', ?) ON CONFLICT (k) DO UPDATE SET v = excluded.v`, hash); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions`); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLite) SaveSession(ctx context.Context, x Session) error {
	if err := s.check(); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions (hash, csrf, created, last, expires, addr, agent) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (hash) DO UPDATE SET last = excluded.last, expires = excluded.expires, addr = excluded.addr`,
		x.TokenHash, x.CSRF, x.Created.UnixMilli(), x.Last.UnixMilli(), x.Expires.UnixMilli(), x.Addr, x.Agent)
	return err
}

func (s *SQLite) SessionByHash(ctx context.Context, hash []byte) (Session, error) {
	if err := s.check(); err != nil {
		return Session{}, err
	}
	x := Session{TokenHash: hash}
	var c, l, e int64
	err := s.db.QueryRowContext(ctx, `SELECT csrf, created, last, expires, addr, agent FROM sessions WHERE hash = ?`, hash).Scan(&x.CSRF, &c, &l, &e, &x.Addr, &x.Agent)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNoSession
	}
	x.Created, x.Last, x.Expires = time.UnixMilli(c), time.UnixMilli(l), time.UnixMilli(e)
	return x, err
}

func (s *SQLite) DeleteSession(ctx context.Context, hash []byte) error {
	if err := s.check(); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE hash = ?`, hash)
	return err
}

func (s *SQLite) DeleteSessions(ctx context.Context) error {
	if err := s.check(); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions`)
	return err
}

func (s *SQLite) PruneSessions(ctx context.Context, now time.Time) error {
	if err := s.check(); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires < ?`, now.UnixMilli())
	return err
}

func (s *SQLite) SavePasskey(ctx context.Context, p Passkey) error {
	if err := s.check(); err != nil {
		return err
	}
	var last any
	if !p.Last.IsZero() {
		last = p.Last.UnixMilli()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO passkeys (id, name, data, created, last) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET name = excluded.name, data = excluded.data, last = excluded.last`,
		p.ID, p.Name, p.Data, p.Created.UnixMilli(), last)
	return err
}

func (s *SQLite) Passkeys(ctx context.Context) ([]Passkey, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, data, created, last FROM passkeys ORDER BY created`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Passkey
	for rows.Next() {
		var p Passkey
		var c int64
		var l sql.NullInt64
		if err := rows.Scan(&p.ID, &p.Name, &p.Data, &c, &l); err != nil {
			return nil, err
		}
		p.Created = time.UnixMilli(c)
		if l.Valid {
			p.Last = time.UnixMilli(l.Int64)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *SQLite) DeletePasskey(ctx context.Context, id []byte) error {
	if err := s.check(); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM passkeys WHERE id = ?`, id)
	return err
}

func (s *SQLite) Overlay(ctx context.Context) (Overlay, error) {
	if err := s.check(); err != nil {
		return Overlay{}, err
	}
	var o Overlay
	var u int64
	err := s.db.QueryRowContext(ctx, `SELECT version, data, updated FROM overlay WHERE id = 1`).Scan(&o.Version, &o.Data, &u)
	if errors.Is(err, sql.ErrNoRows) {
		return Overlay{Data: []byte("{}")}, nil
	}
	o.Updated = time.UnixMilli(u)
	return o, err
}

func (s *SQLite) SaveOverlay(ctx context.Context, expect int64, data []byte) (Overlay, error) {
	if err := s.check(); err != nil {
		return Overlay{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Overlay{}, err
	}
	defer tx.Rollback()
	var cur int64
	if err := tx.QueryRowContext(ctx, `SELECT version FROM overlay WHERE id = 1`).Scan(&cur); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Overlay{}, err
	}
	if cur != expect {
		return Overlay{}, ErrStale
	}
	o := Overlay{Version: cur + 1, Data: data, Updated: time.Now()}
	if _, err := tx.ExecContext(ctx, `INSERT INTO overlay (id, version, data, updated) VALUES (1, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET version = excluded.version, data = excluded.data, updated = excluded.updated`,
		o.Version, o.Data, o.Updated.UnixMilli()); err != nil {
		return Overlay{}, err
	}
	return o, tx.Commit()
}
