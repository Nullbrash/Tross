package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"tross/internal/auth"
	"tross/internal/store"
)

func authServer(t *testing.T) (http.Handler, *store.SQLite) {
	t.Helper()
	st, err := store.Open("", store.DefaultRetention())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return New(Options{
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Store: st, Auth: auth.New(st),
		Devices:         &fakeDevices{devs: map[string]Device{}},
		CAPEM:           func() []byte { return []byte("-----BEGIN CERTIFICATE-----\n") },
		AllowedNetworks: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
	}).Handler(), st
}

type areq struct {
	method, path, body   string
	cookie, csrf, origin string
}

func sendA(h http.Handler, q areq) *httptest.ResponseRecorder {
	r := httptest.NewRequest(q.method, "https://tross.lan"+q.path, strings.NewReader(q.body))
	r.RemoteAddr = "127.0.0.1:5000"
	if q.cookie != "" {
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: q.cookie})
	}
	if q.csrf != "" {
		r.Header.Set(csrfHeader, q.csrf)
	}
	if q.origin != "" {
		r.Header.Set("Origin", q.origin)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestLoginFlow(t *testing.T) {
	h, st := authServer(t)
	// Без пароля — интерфейс узнаёт, что его надо задать на мини-ПК.
	w := sendA(h, areq{method: "GET", path: "/api/auth/state"})
	if !strings.Contains(w.Body.String(), `"password_set":false`) {
		t.Fatalf("state %s", w.Body)
	}
	if w := sendA(h, areq{method: "POST", path: "/api/auth/login", body: `{"password":"whatever-long"}`}); w.Code != http.StatusConflict {
		t.Errorf("no password: %d", w.Code)
	}
	if err := auth.SetPassword(context.Background(), st, "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	// Защищённое — без входа 401, публичное — открыто.
	if w := sendA(h, areq{method: "GET", path: "/api/devices"}); w.Code != http.StatusUnauthorized {
		t.Errorf("devices without login: %d", w.Code)
	}
	for _, p := range []string{"/api/health", "/ca.crt", "/"} {
		if w := sendA(h, areq{method: "GET", path: p}); w.Code == http.StatusUnauthorized {
			t.Errorf("%s needs login", p)
		}
	}
	if w := sendA(h, areq{method: "POST", path: "/api/auth/login", body: `{"password":"wrong password!"}`}); w.Code != http.StatusUnauthorized {
		t.Errorf("wrong password: %d", w.Code)
	}
	w = sendA(h, areq{method: "POST", path: "/api/auth/login", body: `{"password":"correct horse battery"}`})
	if w.Code != 200 {
		t.Fatalf("login: %d %s", w.Code, w.Body)
	}
	var st0 authState
	_ = json.Unmarshal(w.Body.Bytes(), &st0)
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie {
			cookie = c
		}
	}
	if cookie == nil || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || st0.CSRF == "" {
		t.Fatalf("cookie %+v, state %+v", cookie, st0)
	}
	tok := cookie.Value
	if w := sendA(h, areq{method: "GET", path: "/api/devices", cookie: tok}); w.Code != 200 {
		t.Errorf("devices with login: %d", w.Code)
	}
	// Изменение без токена CSRF — отказ; с ним — проходит (404: устройства нет).
	if w := sendA(h, areq{method: "DELETE", path: "/api/devices/dev-x", cookie: tok}); w.Code != http.StatusForbidden {
		t.Errorf("no csrf: %d", w.Code)
	}
	if w := sendA(h, areq{method: "DELETE", path: "/api/devices/dev-x", cookie: tok, csrf: "nope"}); w.Code != http.StatusForbidden {
		t.Errorf("wrong csrf: %d", w.Code)
	}
	if w := sendA(h, areq{method: "DELETE", path: "/api/devices/dev-x", cookie: tok, csrf: st0.CSRF}); w.Code != http.StatusNotFound {
		t.Errorf("with csrf: %d %s", w.Code, w.Body)
	}
	// Чужая страница — отказ ещё до сессии.
	if w := sendA(h, areq{method: "POST", path: "/api/auth/login", body: `{"password":"correct horse battery"}`, origin: "https://evil.example"}); w.Code != http.StatusForbidden {
		t.Errorf("cross-origin login: %d", w.Code)
	}
	if w := sendA(h, areq{method: "DELETE", path: "/api/devices/dev-x", cookie: tok, csrf: st0.CSRF, origin: "https://tross.lan"}); w.Code != http.StatusNotFound {
		t.Errorf("same origin: %d", w.Code)
	}
	// Состояние после входа — с токеном CSRF; заголовки безопасности.
	w = sendA(h, areq{method: "GET", path: "/api/auth/state", cookie: tok})
	if !strings.Contains(w.Body.String(), `"logged_in":true`) || !strings.Contains(w.Body.String(), st0.CSRF) {
		t.Errorf("state after login %s", w.Body)
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Error("no CSP")
	}
	// Версия — только вошедшему.
	if w := sendA(h, areq{method: "GET", path: "/api/health"}); strings.Contains(w.Body.String(), "version") {
		t.Errorf("health without login shows details: %s", w.Body)
	}
	// Выход.
	sendA(h, areq{method: "POST", path: "/api/auth/logout", cookie: tok, csrf: st0.CSRF})
	if w := sendA(h, areq{method: "GET", path: "/api/devices", cookie: tok}); w.Code != http.StatusUnauthorized {
		t.Errorf("after logout: %d", w.Code)
	}
	// Без подключённого входа (и не тест) — защищённое недоступно.
	none := New(Options{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), AllowedNetworks: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}).Handler()
	if w := sendA(none, areq{method: "GET", path: "/api/devices"}); w.Code != http.StatusServiceUnavailable {
		t.Errorf("no auth configured: %d", w.Code)
	}
}

func TestLoginRateLimit(t *testing.T) {
	h, st := authServer(t)
	_ = auth.SetPassword(context.Background(), st, "correct horse battery")
	for range 5 {
		sendA(h, areq{method: "POST", path: "/api/auth/login", body: `{"password":"wrong password!"}`})
	}
	if w := sendA(h, areq{method: "POST", path: "/api/auth/login", body: `{"password":"correct horse battery"}`}); w.Code != http.StatusTooManyRequests {
		t.Errorf("limit: %d", w.Code)
	}
}

func TestRedirectAndCA(t *testing.T) {
	s := New(Options{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), CAPEM: func() []byte { return []byte("PEM") },
		AllowedNetworks: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
	h := s.RedirectHandler("8443")
	r := httptest.NewRequest("GET", "http://tross.lan/devices?x=1", nil)
	r.RemoteAddr = "127.0.0.1:5000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusMovedPermanently || w.Header().Get("Location") != "https://tross.lan:8443/devices?x=1" {
		t.Errorf("redirect %d %q", w.Code, w.Header().Get("Location"))
	}
	r = httptest.NewRequest("GET", "http://tross.lan/ca.crt", nil)
	r.RemoteAddr = "127.0.0.1:5000"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || w.Body.String() != "PEM" {
		t.Errorf("ca over http: %d %q", w.Code, w.Body)
	}
	// Не из LAN — и на HTTP соединение обрывается без ответа.
	if !aborted(h, "/ca.crt", "203.0.113.5:5000") {
		t.Error("outside: answered")
	}
}
