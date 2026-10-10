// Package api — REST API демона (позже — WebSocket) и раздача встроенного
// веб-интерфейса. Доступ только из разрешённых сетей.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"tross/core/model"
	"tross/internal/linkmon"
	"tross/web"
)

type Options struct {
	Log             *slog.Logger
	Monitor         linkmon.LinkMonitor
	AllowedNetworks []netip.Prefix
	Version         string
	DryRun          bool
}

type Server struct {
	opts    Options
	started time.Time
}

func New(opts Options) *Server { return &Server{opts: opts, started: time.Now()} }

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("GET /api/links", s.handleLinks)
	// С методом GET: иначе этот шаблон перехватил бы POST /api/health вместо ответа 405.
	mux.HandleFunc("GET /api/", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	})
	mux.Handle("GET /", http.FileServerFS(web.Dist()))
	return s.allowOnly(mux)
}

// allowOnly пропускает запросы только из разрешённых сетей (LAN и loopback):
// интерфейс управляет сетью всего дома и не должен быть виден снаружи.
func (s *Server) allowOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ap, err := netip.ParseAddrPort(r.RemoteAddr)
		if err != nil || !s.allowed(ap.Addr().Unmap()) {
			s.opts.Log.Warn("api: rejected client", "remote", r.RemoteAddr)
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) allowed(a netip.Addr) bool {
	for _, p := range s.opts.AllowedNetworks {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

type healthResponse struct {
	Status        string `json:"status"`
	Version       string `json:"version"`
	DryRun        bool   `json:"dry_run"`
	UptimeSeconds int64  `json:"uptime_seconds"`
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, healthResponse{
		Status:        "ok",
		Version:       s.opts.Version,
		DryRun:        s.opts.DryRun,
		UptimeSeconds: int64(time.Since(s.started).Seconds()),
	})
}

// linkDTO — плоское представление канала для интерфейса (длительности в мс).
type linkDTO struct {
	ID         model.LinkID    `json:"id"`
	Name       string          `json:"name"`
	Kind       model.LinkKind  `json:"kind"`
	Interface  string          `json:"interface"`
	Metered    bool            `json:"metered"`
	State      model.LinkState `json:"state"`
	StateSince time.Time       `json:"state_since,omitzero"`
	RTTms      float64         `json:"rtt_ms"`
	JitterMs   float64         `json:"jitter_ms"`
	Loss       float64         `json:"loss"`
	DownBps    uint64          `json:"down_bps"`
	UpBps      uint64          `json:"up_bps"`
	UpdatedAt  time.Time       `json:"updated_at,omitzero"`
	Reason     string          `json:"reason,omitempty"`
}

func toLinkDTO(st model.LinkStatus) linkDTO {
	ms := func(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }
	h := st.Health
	return linkDTO{
		ID: st.Link.ID, Name: st.Link.Name, Kind: st.Link.Kind, Interface: st.Link.Interface,
		Metered: st.Link.Metered, State: h.State, StateSince: h.StateSince,
		RTTms: ms(h.RTT), JitterMs: ms(h.Jitter), Loss: h.Loss,
		DownBps: h.Throughput.DownBps, UpBps: h.Throughput.UpBps,
		UpdatedAt: h.UpdatedAt, Reason: h.Reason,
	}
}

func (s *Server) handleLinks(w http.ResponseWriter, _ *http.Request) {
	snap := s.opts.Monitor.Snapshot()
	out := make([]linkDTO, 0, len(snap))
	for _, st := range snap {
		out = append(out, toLinkDTO(st))
	}
	writeJSON(w, http.StatusOK, map[string]any{"links": out})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
