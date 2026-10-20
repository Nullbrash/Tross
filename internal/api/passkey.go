package api

import (
	"context"
	"encoding/base64"
	"net/http"
	"time"

	"tross/internal/auth"
	"tross/internal/store"
)

// Passkeys — ключи доступа (WebAuthn).
type Passkeys interface {
	BeginRegister(ctx context.Context) (any, string, error)
	FinishRegister(ctx context.Context, id, name string, r *http.Request) error
	BeginLogin(ctx context.Context) (any, string, error)
	FinishLogin(ctx context.Context, id string, r *http.Request) (string, auth.Session, error)
	List(ctx context.Context) ([]store.Passkey, error)
	Delete(ctx context.Context, id []byte) error
}

// ceremonyCookie — идентификатор незаконченной регистрации или входа
// (5 минут).
const ceremonyCookie = "tross_passkey"

func (s *Server) passkeyRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/auth/passkey/register/begin", s.passkeyBegin(false))
	mux.HandleFunc("POST /api/auth/passkey/register/finish", s.handlePasskeyRegister)
	mux.HandleFunc("POST /api/auth/passkey/login/begin", s.passkeyBegin(true))
	mux.HandleFunc("POST /api/auth/passkey/login/finish", s.handlePasskeyLogin)
	mux.HandleFunc("GET /api/auth/passkeys", s.handlePasskeys)
	mux.HandleFunc("DELETE /api/auth/passkeys/{id}", s.handlePasskeyDelete)
}

func (s *Server) passkeysOr503(w http.ResponseWriter) bool {
	if s.opts.Passkeys == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "passkeys are not available"})
		return false
	}
	return true
}

func (s *Server) passkeyBegin(login bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.passkeysOr503(w) {
			return
		}
		var opts any
		var id string
		var err error
		if login {
			opts, id, err = s.opts.Passkeys.BeginLogin(r.Context())
		} else {
			opts, id, err = s.opts.Passkeys.BeginRegister(r.Context())
		}
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		http.SetCookie(w, &http.Cookie{Name: ceremonyCookie, Value: id, Path: "/api/auth/passkey/", MaxAge: int((5 * time.Minute).Seconds()),
			Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		writeJSON(w, http.StatusOK, opts)
	}
}

func ceremonyID(r *http.Request) string {
	if c, _ := r.Cookie(ceremonyCookie); c != nil {
		return c.Value
	}
	return ""
}

func (s *Server) handlePasskeyRegister(w http.ResponseWriter, r *http.Request) {
	if !s.passkeysOr503(w) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := s.opts.Passkeys.FinishRegister(r.Context(), ceremonyID(r), r.URL.Query().Get("name"), r); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.opts.Log.Info("api: passkey added", "addr", clientAddr(r))
	s.handlePasskeys(w, r)
}

func (s *Server) handlePasskeyLogin(w http.ResponseWriter, r *http.Request) {
	if !s.passkeysOr503(w) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	tok, x, err := s.opts.Passkeys.FinishLogin(r.Context(), ceremonyID(r), r)
	if err != nil {
		time.Sleep(500 * time.Millisecond)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	s.opts.Log.Info("api: login with a passkey", "addr", clientAddr(r))
	s.setSession(w, tok, x)
	writeJSON(w, http.StatusOK, authState{PasswordSet: true, LoggedIn: true, CSRF: x.CSRF, Passkeys: true})
}

type passkeyDTO struct {
	ID string `json:"id"`
	store.Passkey
}

func (s *Server) handlePasskeys(w http.ResponseWriter, r *http.Request) {
	if !s.passkeysOr503(w) {
		return
	}
	ks, err := s.opts.Passkeys.List(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	out := make([]passkeyDTO, len(ks))
	for i, k := range ks {
		out[i] = passkeyDTO{ID: base64.RawURLEncoding.EncodeToString(k.ID), Passkey: k}
	}
	writeJSON(w, http.StatusOK, map[string]any{"passkeys": out})
}

func (s *Server) handlePasskeyDelete(w http.ResponseWriter, r *http.Request) {
	if !s.passkeysOr503(w) {
		return
	}
	id, err := base64.RawURLEncoding.DecodeString(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad id"})
		return
	}
	if err := s.opts.Passkeys.Delete(r.Context(), id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.handlePasskeys(w, r)
}
