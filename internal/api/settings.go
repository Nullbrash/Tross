package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
)

// Settings — правки интерфейса поверх файла конфигурации.
type Settings interface {
	Get(ctx context.Context) (SettingsDoc, error)
	// Put — новая версия правок поверх version (иначе ErrStale).
	Put(ctx context.Context, version int64, overlay json.RawMessage) (SettingsDoc, error)
}

// SettingsDoc — правки, «как в файле» и что действует сейчас.
type SettingsDoc struct {
	Version int64           `json:"version"`
	Overlay json.RawMessage `json:"overlay"`
	// File — правимые разделы, как в файле (именами полей YAML).
	File json.RawMessage `json:"file"`
	// Applied — версия правок, с которой работает демон; RestartRequired —
	// сохранённое вступит в силу после перезапуска.
	Applied         int64  `json:"applied_version"`
	RestartRequired bool   `json:"restart_required"`
	Error           string `json:"error,omitempty"`
}

// ErrStale — правки изменили с другого устройства, пока их правили здесь.
var ErrStale = errors.New("settings were changed elsewhere: reload them")

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	if s.opts.Settings == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "settings are not available"})
		return
	}
	d, err := s.opts.Settings.Get(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) handleSettingsPut(w http.ResponseWriter, r *http.Request) {
	if s.opts.Settings == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "settings are not available"})
		return
	}
	var req struct {
		Version int64           `json:"version"`
		Overlay json.RawMessage `json:"overlay"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&req); err != nil || len(req.Overlay) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": `want {"version": N, "overlay": {...}}`})
		return
	}
	d, err := s.opts.Settings.Put(r.Context(), req.Version, req.Overlay)
	var re requestError
	switch {
	case errors.Is(err, ErrStale):
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
	case errors.As(err, &re):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	case err != nil:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
	default:
		s.opts.Log.Info("api: interface changes saved", "version", d.Version, "addr", clientAddr(r))
		writeJSON(w, http.StatusOK, d)
	}
}
