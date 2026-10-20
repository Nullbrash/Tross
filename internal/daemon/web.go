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

// settingsAPI — правки интерфейса для API.
type settingsAPI struct {
	path    string
	st      store.AuthStore
	applied int64
	err     string
}

func (s *settingsAPI) Get(ctx context.Context) (api.SettingsDoc, error) {
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
		RestartRequired: o.Version != s.applied, Error: s.err}, nil
}

func (s *settingsAPI) Put(ctx context.Context, version int64, raw json.RawMessage) (api.SettingsDoc, error) {
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
	return s.Get(ctx)
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
