package daemon

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"time"

	"tross/internal/auth"
	"tross/internal/store"
)

// apiSession — вход тестов в API демона: HTTPS (свой корневой — без
// проверки) с cookie сессии и токеном CSRF.
type apiSession struct {
	base        string
	token, csrf string
	client      *http.Client
}

const testPassword = "itest password 123"

func newAPISession(listen string) *apiSession {
	return &apiSession{base: "https://" + listen, client: &http.Client{Timeout: 10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}}
}

// seed — пароль и сессия в базе (до запуска служб — Options.Prepare, или
// в файле базы до запуска службы systemd).
func (a *apiSession) seed(ctx context.Context, st store.AuthStore) error {
	if err := auth.SetPassword(ctx, st, testPassword); err != nil {
		return err
	}
	tok, x, err := auth.New(st).Open(ctx, "127.0.0.1", "itest")
	if err != nil {
		return err
	}
	a.token, a.csrf = tok, x.CSRF
	return nil
}

// prepare — для Options.Prepare.
func (a *apiSession) prepare(ctx context.Context, st *store.SQLite) error { return a.seed(ctx, st) }

// seedFile — то же в файле базы службы (systemd).
func (a *apiSession) seedFile(dataDir string) error {
	st, err := store.Open(filepath.Join(dataDir, dbFile), store.DefaultRetention())
	if err != nil {
		return err
	}
	defer st.Close()
	return a.seed(context.Background(), st)
}

func (a *apiSession) do(method, path string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest(method, a.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.AddCookie(&http.Cookie{Name: "tross_session", Value: a.token})
	if method != http.MethodGet {
		req.Header.Set("X-CSRF-Token", a.csrf)
		req.Header.Set("Content-Type", "application/json")
	}
	return a.client.Do(req)
}

// getJSON — GET с разбором ответа; ошибка — не 200 или не JSON.
func (a *apiSession) getJSON(path string, v any) error {
	resp, err := a.do(http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s %s", path, resp.Status, b)
	}
	return json.Unmarshal(b, v)
}
