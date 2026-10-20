package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"tross/internal/store"
)

// Ключи доступа (WebAuthn): вход отпечатком или лицом с телефона, без
// пароля. Работают только по имени (не по адресу) и только по HTTPS с
// доверенным сертификатом — браузер так требует.

const (
	ceremonyTTL   = 5 * time.Minute
	maxCeremony   = 32
	maxPasskeys   = 16
	maxKeyName    = 40
	ceremonyLogin = "login"
	ceremonyReg   = "register"
)

var (
	ErrCeremony  = errors.New("auth: passkey request expired, start again")
	ErrNoPasskey = errors.New("auth: unknown passkey")
	ErrManyKeys  = errors.New("auth: too many passkeys")
)

// Один пользователь — владелец; идентификатор постоянный.
var userHandle = func() []byte { h := sha256.Sum256([]byte("tross-owner")); return h[:16] }()

type owner struct{ creds []webauthn.Credential }

func (owner) WebAuthnID() []byte                           { return userHandle }
func (owner) WebAuthnName() string                         { return "owner" }
func (owner) WebAuthnDisplayName() string                  { return "Tross" }
func (o owner) WebAuthnCredentials() []webauthn.Credential { return o.creds }

type ceremony struct {
	kind    string
	data    webauthn.SessionData
	expires time.Time
}

// Passkeys — регистрация и вход по ключам доступа.
type Passkeys struct {
	wa   *webauthn.WebAuthn
	st   store.AuthStore
	auth *Service

	mu   sync.Mutex
	open map[string]ceremony
}

// NewPasskeys — rpID — имя интерфейса (tross.lan), origin — его адрес
// HTTPS (с портом, если не 443).
func NewPasskeys(rpID, origin string, st store.AuthStore, a *Service) (*Passkeys, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: "Tross",
		RPOrigins:     []string{origin},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		},
	})
	if err != nil {
		return nil, err
	}
	return &Passkeys{wa: wa, st: st, auth: a, open: map[string]ceremony{}}, nil
}

func (p *Passkeys) owner(ctx context.Context) (owner, error) {
	ks, err := p.st.Passkeys(ctx)
	if err != nil {
		return owner{}, err
	}
	var o owner
	for _, k := range ks {
		var c webauthn.Credential
		if json.Unmarshal(k.Data, &c) == nil {
			o.creds = append(o.creds, c)
		}
	}
	return o, nil
}

func (p *Passkeys) remember(kind string, d *webauthn.SessionData) (string, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	id := base64.RawURLEncoding.EncodeToString(b)
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, c := range p.open {
		if now.After(c.expires) {
			delete(p.open, k)
		}
	}
	if len(p.open) >= maxCeremony {
		return "", ErrCeremony
	}
	p.open[id] = ceremony{kind: kind, data: *d, expires: now.Add(ceremonyTTL)}
	return id, nil
}

func (p *Passkeys) take(id, kind string) (webauthn.SessionData, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	c, ok := p.open[id]
	delete(p.open, id)
	if !ok || c.kind != kind || time.Now().After(c.expires) {
		return webauthn.SessionData{}, ErrCeremony
	}
	return c.data, nil
}

// BeginRegister — параметры для браузера (после входа по паролю).
func (p *Passkeys) BeginRegister(ctx context.Context) (any, string, error) {
	o, err := p.owner(ctx)
	if err != nil {
		return nil, "", err
	}
	if len(o.creds) >= maxPasskeys {
		return nil, "", ErrManyKeys
	}
	var excl []protocol.CredentialDescriptor
	for _, c := range o.creds {
		excl = append(excl, c.Descriptor())
	}
	opts, sd, err := p.wa.BeginRegistration(o, webauthn.WithExclusions(excl))
	if err != nil {
		return nil, "", err
	}
	id, err := p.remember(ceremonyReg, sd)
	return opts, id, err
}

// FinishRegister — ответ браузера; name — подпись ключа («телефон»).
func (p *Passkeys) FinishRegister(ctx context.Context, id, name string, r *http.Request) error {
	sd, err := p.take(id, ceremonyReg)
	if err != nil {
		return err
	}
	o, err := p.owner(ctx)
	if err != nil {
		return err
	}
	cred, err := p.wa.FinishRegistration(o, sd, r)
	if err != nil {
		return err
	}
	data, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = "passkey"
	}
	if r := []rune(name); len(r) > maxKeyName {
		name = string(r[:maxKeyName])
	}
	return p.st.SavePasskey(ctx, store.Passkey{ID: cred.ID, Name: name, Data: data, Created: time.Now()})
}

// BeginLogin — вход без пароля: браузер сам предложит ключ.
func (p *Passkeys) BeginLogin(context.Context) (any, string, error) {
	opts, sd, err := p.wa.BeginDiscoverableLogin()
	if err != nil {
		return nil, "", err
	}
	id, err := p.remember(ceremonyLogin, sd)
	return opts, id, err
}

// FinishLogin — проверка ответа браузера; удачно — новая сессия.
func (p *Passkeys) FinishLogin(ctx context.Context, id string, r *http.Request) (string, Session, error) {
	sd, err := p.take(id, ceremonyLogin)
	if err != nil {
		return "", Session{}, err
	}
	o, err := p.owner(ctx)
	if err != nil {
		return "", Session{}, err
	}
	if len(o.creds) == 0 {
		return "", Session{}, ErrNoPasskey
	}
	handler := func(rawID, uh []byte) (webauthn.User, error) {
		if !bytes.Equal(uh, userHandle) {
			return nil, ErrNoPasskey
		}
		return o, nil
	}
	cred, err := p.wa.FinishDiscoverableLogin(handler, sd, r)
	if err != nil {
		return "", Session{}, err
	}
	ks, _ := p.st.Passkeys(ctx)
	for _, k := range ks {
		if bytes.Equal(k.ID, cred.ID) {
			k.Data, _ = json.Marshal(cred) // счётчик подписей
			k.Last = time.Now()
			_ = p.st.SavePasskey(ctx, k)
		}
	}
	return p.auth.Open(ctx, clientOf(r), r.UserAgent())
}

func (p *Passkeys) List(ctx context.Context) ([]store.Passkey, error) { return p.st.Passkeys(ctx) }

func (p *Passkeys) Delete(ctx context.Context, id []byte) error { return p.st.DeletePasskey(ctx, id) }

func clientOf(r *http.Request) string {
	h := r.RemoteAddr
	if i := strings.LastIndexByte(h, ':'); i > 0 {
		h = h[:i]
	}
	return strings.Trim(h, "[]")
}
