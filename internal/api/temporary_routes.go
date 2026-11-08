package api

import (
	"encoding/json"
	"net/http"
)

func (s *Server) temporaryOr503(w http.ResponseWriter) bool {
	if s.opts.TemporaryForwards == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "temporary forwards are not available"})
		return false
	}
	return true
}

func (s *Server) handleTemporaryForwards(w http.ResponseWriter, r *http.Request) {
	if !s.temporaryOr503(w) {
		return
	}
	items, err := s.opts.TemporaryForwards.ListTemporaryForwards(r.Context())
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"forwards": items})
}

func (s *Server) handleTemporaryForwardOpen(w http.ResponseWriter, r *http.Request) {
	if !s.temporaryOr503(w) {
		return
	}
	var req TemporaryForwardRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid temporary forward"})
		return
	}
	item, err := s.opts.TemporaryForwards.OpenTemporaryForward(r.Context(), req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) handleTemporaryForwardClose(w http.ResponseWriter, r *http.Request) {
	if !s.temporaryOr503(w) {
		return
	}
	if err := s.opts.TemporaryForwards.CloseTemporaryForward(r.Context(), r.PathValue("id")); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"closed": r.PathValue("id")})
}
