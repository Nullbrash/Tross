package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"tross/internal/api"
	"tross/internal/auth"
	"tross/internal/config"
	"tross/internal/store"
	"tross/internal/tlsca"
)

// webTLS — свой корневой и сертификат интерфейса на имя и адреса API.
func webTLS(cfg *config.Config, log *slog.Logger) (*tlsca.CA, error) {
	dir := cfg.API.TLSDir
	if dir == "" && cfg.Daemon.DataDir != "" {
		dir = filepath.Join(cfg.Daemon.DataDir, "tls")
	}
	var addrs []netip.Addr
	add := func(hp string) {
		if ap, err := netip.ParseAddrPort(hp); err == nil && !slices.Contains(addrs, ap.Addr()) {
			addrs = append(addrs, ap.Addr())
		}
	}
	add(cfg.API.Listen)
	if cfg.API.HTTPListen != "" {
		add(cfg.API.HTTPListen)
	}
	if g := cfg.LAN.DHCP.Gateway; g.IsValid() && !slices.Contains(addrs, g) {
		addrs = append(addrs, g)
	}
	nets := slices.Clone(cfg.LAN.Networks)
	for _, a := range addrs {
		if !slices.ContainsFunc(nets, func(p netip.Prefix) bool { return p.Contains(a) }) {
			nets = append(nets, netip.PrefixFrom(a, 32))
		}
	}
	ca, err := tlsca.Load(tlsca.Config{Dir: dir, Names: []string{cfg.API.Name}, Addrs: addrs, Networks: nets})
	if err != nil {
		return nil, err
	}
	if ca.Renewed {
		log.Warn("api: new root certificate: install it again on phones and PCs (/ca.crt)", "fingerprint", ca.Fingerprint())
	}
	if _, err := ca.Server(); err != nil {
		return nil, err
	}
	log.Info("api: certificate ready", "name", cfg.API.Name, "root_fingerprint", ca.Fingerprint())
	return ca, nil
}

// passkeyOrigin — адрес интерфейса по имени (ключи доступа — только по
// имени).
func passkeyOrigin(cfg *config.Config) string {
	_, port, _ := net.SplitHostPort(cfg.API.Listen)
	if port == "443" || port == "" {
		return "https://" + cfg.API.Name
	}
	return "https://" + cfg.API.Name + ":" + port
}

// loadOverlay — правки интерфейса поверх файла при запуске; неверные (файл
// изменился) — работа по файлу и ошибка в API.
func loadOverlay(ctx context.Context, cfg *config.Config, path string, st store.AuthStore, log *slog.Logger) (*config.Config, int64, string) {
	if path == "" {
		return cfg, 0, ""
	}
	o, err := st.Overlay(ctx)
	if err != nil {
		return cfg, 0, err.Error()
	}
	ov, err := config.ParseOverlay(o.Data)
	if err == nil && ov.Empty() {
		return cfg, o.Version, ""
	}
	var merged *config.Config
	if err == nil {
		merged, err = config.LoadWithOverlay(path, ov)
	}
	if err != nil {
		log.Error("interface changes are not applied: working by the config file", "version", o.Version, "err", err)
		return cfg, 0, err.Error()
	}
	merged.Daemon.DryRun = cfg.Daemon.DryRun
	merged.SetDataDir(cfg.Daemon.DataDir)
	log.Info("interface changes applied over the config file", "version", o.Version)
	return merged, o.Version, ""
}

// recoverConfigTrial восстанавливает сохраненный набор до первого чтения
// overlay. Так перезапуск или авария во время пробы не оставляет кандидата
// действующим без подтверждения из LAN.
func recoverConfigTrial(ctx context.Context, st store.AuthStore, log *slog.Logger) error {
	t, err := st.ConfigTrial(ctx)
	if err != nil || len(t.Candidate) == 0 {
		return err
	}
	if t.Confirmed {
		return st.DeleteConfigTrial(ctx)
	}
	if _, err := config.ParseOverlay(t.Previous); err != nil {
		return fmt.Errorf("trial recovery document: %w", err)
	}
	o, err := st.Overlay(ctx)
	if err != nil {
		return err
	}
	if _, err := st.SaveOverlay(ctx, o.Version, t.Previous); err != nil {
		return fmt.Errorf("trial recovery overlay: %w", err)
	}
	if err := st.DeleteConfigTrial(ctx); err != nil {
		return err
	}
	log.Warn("interface trial was not confirmed; previous settings restored")
	return nil
}

// settingsAPI — правки интерфейса для API.
type settingsAPI struct {
	mu      sync.Mutex
	path    string
	st      store.AuthStore
	applied int64
	err     string
	// active — снимок проверенных правимых разделов после overlay при старте.
	active    json.RawMessage
	apply     func(context.Context, *config.Config) error
	prepare   func(*config.Config)
	lifetime  context.Context
	trialStop chan struct{}
}

func (s *settingsAPI) Trial(ctx context.Context) (api.TrialDoc, error) {
	t, err := s.st.ConfigTrial(ctx)
	return api.TrialDoc{Active: len(t.Candidate) != 0, Expires: t.Expires, Confirmed: t.Confirmed}, err
}

func (s *settingsAPI) StartTrial(ctx context.Context) (api.TrialDoc, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, err := s.st.ConfigTrial(ctx); err != nil {
		return api.TrialDoc{}, err
	} else if len(t.Candidate) != 0 {
		return api.TrialDoc{}, api.ErrBadRequest(errors.New("interface trial is already active"))
	}
	o, err := s.st.Overlay(ctx)
	if err != nil {
		return api.TrialDoc{}, err
	}
	// Кандидат — нормализованные правимые разделы, а не неразобранный JSON клиента.
	ov, err := config.ParseOverlay(o.Data)
	if err != nil {
		return api.TrialDoc{}, err
	}
	cfg, err := config.LoadWithOverlay(s.path, ov)
	if err != nil {
		return api.TrialDoc{}, err
	}
	s.prepareConfig(cfg)
	candidate, err := config.FileSections(cfg)
	if err != nil {
		return api.TrialDoc{}, err
	}
	m := config.TrialManager{Store: s.st}
	t, err := m.Begin(ctx, s.active, candidate, 90*time.Second)
	if err != nil {
		return api.TrialDoc{}, err
	}
	if err := s.apply(ctx, cfg); err != nil {
		_ = s.st.DeleteConfigTrial(ctx)
		return api.TrialDoc{}, err
	}
	s.active, s.applied = candidate, o.Version
	s.startTimerLocked(t)
	return api.TrialDoc{Active: true, Expires: t.Expires}, nil
}

func (s *settingsAPI) ConfirmTrial(ctx context.Context) (api.TrialDoc, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := config.TrialManager{Store: s.st}
	if err := m.Confirm(ctx); err != nil {
		return api.TrialDoc{}, err
	}
	if err := s.st.DeleteConfigTrial(ctx); err != nil {
		return api.TrialDoc{}, err
	}
	s.stopTimerLocked()
	return api.TrialDoc{}, nil
}

func (s *settingsAPI) startTimerLocked(t store.ConfigTrial) {
	s.stopTimerLocked()
	stop := make(chan struct{})
	s.trialStop = stop
	go func() {
		d := time.Until(t.Expires)
		if d < 0 {
			d = 0
		}
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-timer.C:
			if err := s.rollback(context.Background()); err != nil {
				// Журнал остаётся: следующий запуск обязательно повторит откат.
				return
			}
		case <-stop:
		case <-s.done():
		}
	}()
}

func (s *settingsAPI) done() <-chan struct{} {
	if s.lifetime == nil {
		return nil
	}
	return s.lifetime.Done()
}

func (s *settingsAPI) stopTimerLocked() {
	if s.trialStop != nil {
		close(s.trialStop)
		s.trialStop = nil
	}
}

func (s *settingsAPI) rollback(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.st.ConfigTrial(ctx)
	if err != nil || len(t.Candidate) == 0 || t.Confirmed || time.Now().Before(t.Expires) {
		return err
	}
	cfg, err := s.configFromSections(t.Previous)
	if err != nil {
		return err
	}
	if err := s.apply(ctx, cfg); err != nil {
		return err
	}
	o, err := s.st.Overlay(ctx)
	if err != nil {
		return err
	}
	o, err = s.st.SaveOverlay(ctx, o.Version, t.Previous)
	if err != nil {
		return err
	}
	if err := s.st.DeleteConfigTrial(ctx); err != nil {
		return err
	}
	s.active, s.applied = t.Previous, o.Version
	s.stopTimerLocked()
	return nil
}

func (s *settingsAPI) configFromSections(raw []byte) (*config.Config, error) {
	ov, err := config.ParseOverlay(raw)
	if err != nil {
		return nil, err
	}
	cfg, err := config.LoadWithOverlay(s.path, ov)
	if err != nil {
		return nil, err
	}
	s.prepareConfig(cfg)
	return cfg, nil
}

func (s *settingsAPI) prepareConfig(cfg *config.Config) {
	if s.prepare != nil {
		s.prepare(cfg)
	}
}

func (s *settingsAPI) Get(ctx context.Context) (api.SettingsDoc, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getLocked(ctx)
}

func (s *settingsAPI) getLocked(ctx context.Context) (api.SettingsDoc, error) {
	o, err := s.st.Overlay(ctx)
	if err != nil {
		return api.SettingsDoc{}, err
	}
	file, err := config.Load(s.path)
	if err != nil {
		return api.SettingsDoc{}, err
	}
	fs, err := config.FileSections(file)
	if err != nil {
		return api.SettingsDoc{}, err
	}
	return api.SettingsDoc{Version: o.Version, Overlay: json.RawMessage(o.Data), File: fs, Applied: s.applied,
		Active: s.active, RestartRequired: o.Version != s.applied, Error: s.err}, nil
}

func (s *settingsAPI) Put(ctx context.Context, version int64, raw json.RawMessage) (api.SettingsDoc, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, err := s.st.ConfigTrial(ctx); err != nil {
		return api.SettingsDoc{}, err
	} else if len(t.Candidate) != 0 {
		return api.SettingsDoc{}, api.ErrBadRequest(errors.New("finish or wait for the active interface trial"))
	}
	ov, err := config.ParseOverlay(raw)
	if err == nil {
		_, err = config.LoadWithOverlay(s.path, ov)
	}
	if err != nil {
		return api.SettingsDoc{}, api.ErrBadRequest(err)
	}
	// Хранится нормализованный документ: то, что понял разбор.
	norm, err := config.ToJSON(ov)
	if err != nil {
		return api.SettingsDoc{}, err
	}
	if _, err := s.st.SaveOverlay(ctx, version, norm); errors.Is(err, store.ErrStale) {
		return api.SettingsDoc{}, api.ErrStale
	} else if err != nil {
		return api.SettingsDoc{}, err
	}
	return s.getLocked(ctx)
}

// serveHTTP — HTTP: перенаправление на HTTPS и корневой сертификат.
func serveHTTP(ctx context.Context, cfg *config.Config, h *api.Server, log *slog.Logger) error {
	_, port, _ := net.SplitHostPort(cfg.API.Listen)
	srv := &http.Server{Addr: cfg.API.HTTPListen, Handler: h.RedirectHandler(port), ReadHeaderTimeout: 5 * time.Second,
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn)}
	ln, err := net.Listen("tcp", cfg.API.HTTPListen)
	if err != nil {
		return fmt.Errorf("api http listen: %w", err)
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	if err := srv.Serve(h.Listener(ln)); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// webAuth — вход и ключи доступа.
func webAuth(cfg *config.Config, st store.AuthStore, log *slog.Logger) (*auth.Service, *auth.Passkeys) {
	a := auth.New(st)
	pk, err := auth.NewPasskeys(cfg.API.Name, passkeyOrigin(cfg), st, a)
	if err != nil {
		log.Warn("api: passkeys are off", "err", err)
		return a, nil
	}
	return a, pk
}
