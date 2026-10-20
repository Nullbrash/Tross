package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"tross/internal/auth"
)

const (
	sessionCookie = "tross_session"
	csrfHeader    = "X-CSRF-Token"
)

// public — маршруты без входа: вход, состояние входа, здоровье, статика
// интерфейса и корневой сертификат.
func public(r *http.Request) bool {
	p := r.URL.Path
	switch {
	case p == "/api/health", p == "/api/auth/login", p == "/api/auth/state", p == "/ca.crt":
		return true
	case strings.HasPrefix(p, "/api/auth/passkey/login"):
		return true
	case !strings.HasPrefix(p, "/api/"):
		return true
	}
	return false
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// requireAuth — сессия для всего, кроме public; для изменяющих запросов —
// ещё токен CSRF в заголовке и Origin своего хоста (если браузер его
// прислал).
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !safeMethod(r.Method) && !sameOrigin(r) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-origin request"})
			return
		}
		if public(r) {
			next.ServeHTTP(w, r)
			return
		}
		if s.opts.NoAuth {
			next.ServeHTTP(w, r)
			return
		}
		if s.opts.Auth == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "login is not available"})
			return
		}
		c, _ := r.Cookie(sessionCookie)
		tok := ""
		if c != nil {
			tok = c.Value
		}
		x, err := s.opts.Auth.Check(r.Context(), tok, clientAddr(r))
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
			return
		}
		if !safeMethod(r.Method) && !auth.CheckCSRF(x, r.Header.Get(csrfHeader)) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "missing or wrong " + csrfHeader})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// sameOrigin — Origin (если есть) совпадает с хостом запроса.
func sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return true
	}
	u, err := url.Parse(o)
	return err == nil && u.Host == r.Host
}

func clientAddr(r *http.Request) string {
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return ap.Addr().Unmap().String()
	}
	return ""
}

// securityHeaders — интерфейс не встраивается в чужие страницы, скрипты —
// только свои.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) setSession(w http.ResponseWriter, tok string, x auth.Session) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: tok, Path: "/", Expires: x.Expires,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

type authState struct {
	PasswordSet bool   `json:"password_set"`
	LoggedIn    bool   `json:"logged_in"`
	CSRF        string `json:"csrf,omitempty"`
	Passkeys    bool   `json:"passkeys"`
}

// handleAuthState — задан ли пароль, вошёл ли браузер (и его токен CSRF).
func (s *Server) handleAuthState(w http.ResponseWriter, r *http.Request) {
	if s.opts.Auth == nil {
		writeJSON(w, http.StatusOK, authState{LoggedIn: s.opts.NoAuth})
		return
	}
	set, err := s.opts.Auth.HasPassword(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	st := authState{PasswordSet: set, Passkeys: s.opts.Passkeys != nil}
	if c, _ := r.Cookie(sessionCookie); c != nil {
		if x, err := s.opts.Auth.Check(r.Context(), c.Value, clientAddr(r)); err == nil {
			st.LoggedIn, st.CSRF = true, x.CSRF
		}
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.opts.Auth == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "login is not available"})
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": `want {"password": "..."}`})
		return
	}
	tok, x, err := s.opts.Auth.Login(r.Context(), req.Password, clientAddr(r), r.UserAgent())
	switch {
	case errors.Is(err, auth.ErrTooMany):
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": err.Error()})
		return
	case errors.Is(err, auth.ErrBadLogin):
		// Неудача — чуть позже: подбор и так ограничен, а мгновенный ответ
		// облегчал бы его.
		time.Sleep(500 * time.Millisecond)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	case errors.Is(err, auth.ErrNoPassword):
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	case err != nil:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.opts.Log.Info("api: login", "addr", clientAddr(r))
	s.setSession(w, tok, x)
	writeJSON(w, http.StatusOK, authState{PasswordSet: true, LoggedIn: true, CSRF: x.CSRF, Passkeys: s.opts.Passkeys != nil})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, _ := r.Cookie(sessionCookie); c != nil && s.opts.Auth != nil {
		_ = s.opts.Auth.Logout(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, authState{PasswordSet: true})
}

// handleCA — корневой сертификат для установки на телефон и ПК.
func (s *Server) handleCA(w http.ResponseWriter, _ *http.Request) {
	if s.opts.CAPEM == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no certificate"})
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="tross-ca.crt"`)
	_, _ = w.Write(s.opts.CAPEM())
}

// RedirectHandler — HTTP: корневой сертификат и перенаправление на HTTPS.
func (s *Server) RedirectHandler(httpsPort string) http.Handler {
	return s.allowOnly(securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ca.crt" && safeMethod(r.Method) {
			s.handleCA(w, r)
			return
		}
		host := r.Host
		if h, _, ok := strings.Cut(host, ":"); ok {
			host = h
		}
		if httpsPort != "443" {
			host += ":" + httpsPort
		}
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently)
	})))
}
