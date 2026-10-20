package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strconv"

	"tross/core/model"
	"tross/internal/dataplane"
	"tross/internal/upnp"
)

// UPnP — пробросы по запросу программ.
type UPnP interface {
	Status(ctx context.Context) (UPnPStatus, error)
	// Resolve — решение по ожидающему запросу: once, always, deny.
	Resolve(ctx context.Context, id, decision string) error
	Close(ctx context.Context, proto model.Protocol, port uint16) error
}

type UPnPStatus struct {
	Enabled    bool           `json:"enabled"`
	ExternalIP netip.Addr     `json:"external_ip,omitzero"`
	Mappings   []UPnPMapping  `json:"mappings"`
	Pending    []upnp.Pending `json:"pending"`
}

type UPnPMapping struct {
	dataplane.UPnPMapping
	ExpiresSeconds int    `json:"expires_seconds"`
	Device         string `json:"device,omitempty"`
	Name           string `json:"name,omitempty"`
}

var (
	ErrUPnPOff   = errors.New("upnp is off")
	ErrNoPending = errors.New("no such request or mapping")
)

func writeUPnPErr(w http.ResponseWriter, err error) {
	var re requestError
	switch {
	case errors.Is(err, ErrUPnPOff):
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
	case errors.Is(err, ErrNoPending):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
	case errors.As(err, &re):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
}

func (s *Server) handleUPnP(w http.ResponseWriter, r *http.Request) {
	if s.opts.UPnP == nil {
		writeJSON(w, http.StatusOK, UPnPStatus{})
		return
	}
	st, err := s.opts.UPnP.Status(r.Context())
	if err != nil {
		writeUPnPErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// handleUPnPResolve — POST /api/upnp/pending/{id} {"decision": "once|always|deny"}.
func (s *Server) handleUPnPResolve(w http.ResponseWriter, r *http.Request) {
	if s.opts.UPnP == nil {
		writeUPnPErr(w, ErrUPnPOff)
		return
	}
	var req struct {
		Decision string `json:"decision"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": `want {"decision": "once|always|deny"}`})
		return
	}
	if err := s.opts.UPnP.Resolve(r.Context(), r.PathValue("id"), req.Decision); err != nil {
		writeUPnPErr(w, err)
		return
	}
	s.handleUPnP(w, r)
}

// handleUPnPClose — DELETE /api/upnp/mappings/{proto}/{port}.
func (s *Server) handleUPnPClose(w http.ResponseWriter, r *http.Request) {
	if s.opts.UPnP == nil {
		writeUPnPErr(w, ErrUPnPOff)
		return
	}
	proto := model.Protocol(r.PathValue("proto"))
	port, err := strconv.ParseUint(r.PathValue("port"), 10, 16)
	if err != nil || proto != model.ProtoTCP && proto != model.ProtoUDP {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "want /api/upnp/mappings/tcp|udp/<port>"})
		return
	}
	if err := s.opts.UPnP.Close(r.Context(), proto, uint16(port)); err != nil {
		writeUPnPErr(w, err)
		return
	}
	s.handleUPnP(w, r)
}
