// Package api — REST API демона (позже — WebSocket) и раздача встроенного
// веб-интерфейса. Доступ только из разрешённых сетей.
package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"tross/core/model"
	"tross/internal/dataplane"
	"tross/internal/linkmon"
	"tross/internal/logring"
	"tross/internal/store"
	"tross/web"
)

type Options struct {
	Log     *slog.Logger
	Monitor linkmon.LinkMonitor
	Store   store.Store
	Logs    *logring.Ring
	// System — последняя выборка загрузки машины; nil — выборок нет.
	System func() *store.SystemSample
	// EventDrops — сколько событий шина потеряла на переполненных подписчиках.
	EventDrops func() uint64
	// Connections — снимок размеченных соединений; nil — недоступно.
	Connections func(ctx context.Context) ([]dataplane.Connection, error)
	// Explain — «почему так» для соединения; nil — недоступно.
	Explain ExplainFunc
	// SQM — очереди CAKE каналов (только каналы с SQM); nil — недоступно.
	SQM func() map[model.LinkID]SQMStatus
	// DNS — резолвер дома; nil — не запущен (сухой режим).
	DNS func(ctx context.Context) DNSStatus
	// Lists — списки и ручные правила; nil — недоступно.
	Lists Lists
	// Devices — реестр устройств; nil — недоступен.
	Devices         Devices
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
	mux.HandleFunc("POST /api/links/{id}/speedtest", s.handleSpeedTest)
	mux.HandleFunc("GET /api/links/{id}/stats", s.handleLinkStats)
	mux.HandleFunc("GET /api/system/stats", s.handleSystemStats)
	mux.HandleFunc("GET /api/events", s.handleEvents)
	mux.HandleFunc("GET /api/logs", s.handleLogs)
	mux.HandleFunc("GET /api/metrics", s.handleMetrics)
	mux.HandleFunc("GET /api/connections", s.handleConnections)
	mux.HandleFunc("GET /api/explain", s.handleExplain)
	mux.HandleFunc("GET /api/dns", s.handleDNS)
	mux.HandleFunc("GET /api/lists", s.handleLists)
	mux.HandleFunc("POST /api/lists/refresh", s.handleListsRefresh)
	mux.HandleFunc("POST /api/lists/manual", s.handleManualAdd)
	mux.HandleFunc("DELETE /api/lists/manual", s.handleManualDelete)
	mux.HandleFunc("GET /api/devices", s.handleDevices)
	mux.HandleFunc("GET /api/devices/{id}", s.handleDevice)
	mux.HandleFunc("PATCH /api/devices/{id}", s.handleDeviceUpdate)
	mux.HandleFunc("POST /api/devices/{id}/merge", s.handleDeviceMerge)
	mux.HandleFunc("POST /api/devices/{id}/dismiss", s.handleDeviceDismiss)
	mux.HandleFunc("DELETE /api/devices/{id}", s.handleDeviceForget)
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
	SQM        *SQMStatus      `json:"sqm,omitempty"`
}

// SQMDirection — очередь одного направления канала.
type SQMDirection struct {
	RateBps uint64  `json:"rate_bps"` // 0 — без ограничения
	BaseBps uint64  `json:"base_bps"`
	Basis   string  `json:"basis,omitempty"` // manual | test | passive | restored
	Pct     float64 `json:"pct"`
}

// SQMStatus — очереди CAKE канала: скорость = база × процент.
type SQMStatus struct {
	Down    SQMDirection `json:"down"`
	Up      SQMDirection `json:"up"`
	Testing bool         `json:"testing,omitempty"` // идёт тест скорости — загрузка без ограничения
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
	var sqm map[model.LinkID]SQMStatus
	if s.opts.SQM != nil {
		sqm = s.opts.SQM()
	}
	out := make([]linkDTO, 0, len(snap))
	for _, st := range snap {
		d := toLinkDTO(st)
		if q, ok := sqm[st.Link.ID]; ok {
			d.SQM = &q
		}
		out = append(out, d)
	}
	writeJSON(w, http.StatusOK, map[string]any{"links": out})
}

// handleSpeedTest — активный замер по команде; на лимитированных каналах это
// единственный способ его запустить (автоматически они не тестируются).
func (s *Server) handleSpeedTest(w http.ResponseWriter, r *http.Request) {
	id := model.LinkID(r.PathValue("id"))
	if _, ok := s.opts.Monitor.Status(id); !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown link"})
		return
	}
	th, err := s.opts.Monitor.SpeedTest(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"link": id, "down_bps": th.DownBps, "measured_at": th.MeasuredAt})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
