package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	coredns "tross/core/dns"
	corelists "tross/core/lists"
	"tross/core/model"
)

// DNSStatus — резолвер дома. Имён по устройствам здесь нет: они пишутся
// только в отладочный журнал, и читать его можно лишь на самом мини-ПК.
type DNSStatus struct {
	Queries   uint64        `json:"queries"`
	CacheHits uint64        `json:"cache_hits"`
	Failures  uint64        `json:"failures"`
	AvgUpTime time.Duration `json:"avg_upstream"`
	// Serving — кто отвечает дому: "resolver" или "fallback".
	Serving   string                   `json:"serving"`
	Upstreams []coredns.UpstreamHealth `json:"upstreams"`
	Debug     DNSDebug                 `json:"debug"`
	// EncryptedDNS — устройства со своим зашифрованным DNS: классы по домену
	// для них не работают (их DNS мимо резолвера).
	EncryptedDNS []EncryptedDNS `json:"encrypted_dns"`
	// Links — перехватывает ли канал обычный DNS (провайдер подменяет
	// ответы); nil — ещё не проверялось.
	Links []LinkDNS `json:"links"`
}

type DNSDebug struct {
	Active bool      `json:"active"`
	Until  time.Time `json:"until,omitzero"`
}

type EncryptedDNS struct {
	Device string `json:"device"`
	// Kind — "dot" (порт 853) или "doh" (известный адрес DoH на 443).
	Kind         string   `json:"kind"`
	Destinations []string `json:"destinations"`
}

type LinkDNS struct {
	Link        model.LinkID `json:"link"`
	Intercepted *bool        `json:"intercepted,omitempty"`
	CheckedAt   time.Time    `json:"checked_at,omitzero"`
}

// Lists — онлайн-списки и ручные правила.
type Lists interface {
	Sources() []corelists.SourceStatus
	Refresh(ctx context.Context, id string) error
	Manual() []model.DomainRule
	// AddManual — своё правило (хранится в базе, вместе с правилами конфига).
	AddManual(ctx context.Context, r ManualRule) error
	DeleteManual(ctx context.Context, pattern string, match model.MatchKind) error
}

// ManualRule — своё правило из API.
type ManualRule struct {
	Domain  string             `json:"domain"`
	Exact   bool               `json:"exact"`
	Purpose model.ListPurpose  `json:"purpose"`
	Class   model.TrafficClass `json:"class,omitempty"`
}

func (s *Server) handleDNS(w http.ResponseWriter, r *http.Request) {
	if s.opts.DNS == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "resolver is not running"})
		return
	}
	writeJSON(w, http.StatusOK, s.opts.DNS(r.Context()))
}

func (s *Server) handleLists(w http.ResponseWriter, _ *http.Request) {
	if s.opts.Lists == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "lists are not available"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sources": s.opts.Lists.Sources(), "manual": s.opts.Lists.Manual()})
}

// handleListsRefresh — загрузить источник сейчас (?source=; пусто — все).
func (s *Server) handleListsRefresh(w http.ResponseWriter, r *http.Request) {
	if s.opts.Lists == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "lists are not available"})
		return
	}
	if err := s.opts.Lists.Refresh(r.Context(), r.URL.Query().Get("source")); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sources": s.opts.Lists.Sources()})
}

func (s *Server) handleManualAdd(w http.ResponseWriter, r *http.Request) {
	if s.opts.Lists == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "lists are not available"})
		return
	}
	var m ManualRule
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&m); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := s.opts.Lists.AddManual(r.Context(), m); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"manual": s.opts.Lists.Manual()})
}

func (s *Server) handleManualDelete(w http.ResponseWriter, r *http.Request) {
	if s.opts.Lists == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "lists are not available"})
		return
	}
	q := r.URL.Query()
	match := model.MatchKind(q.Get("match"))
	if match == "" {
		match = model.MatchSuffix
	}
	err := s.opts.Lists.DeleteManual(r.Context(), q.Get("domain"), match)
	switch {
	case errors.Is(err, ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	case err != nil:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"manual": s.opts.Lists.Manual()})
}

// ErrNotFound — такого правила нет (или оно из конфига: правится там).
var ErrNotFound = errors.New("no such rule added through the API")
