package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"tross/core/model"
	"tross/internal/store"
)

// Devices — реестр устройств.
type Devices interface {
	List() []Device
	Get(ctx context.Context, id string) (DeviceDetail, error)
	Update(ctx context.Context, id string, e DeviceEdit) (Device, error)
	// Merge вливает запись src в dst: настройки dst остаются, MAC и адрес
	// src переходят к ней (ответ на предложение «похоже на…»).
	Merge(ctx context.Context, dst, src string) (Device, error)
	// Dismiss — «это другое устройство»: предложение снимается навсегда.
	Dismiss(ctx context.Context, id string) (Device, error)
	Forget(ctx context.Context, id string) error
}

// Device — запись реестра и то, что из неё следует.
type Device struct {
	model.Device
	Online        bool            `json:"online"`
	SuggestedName string          `json:"suggested_name,omitempty"`
	UPnPEffective model.UPnPLevel `json:"upnp_effective"`
	// DNSModeFrom — откуда режим DNS: config (раздел dns.devices — правится
	// там), device (задан для устройства), default.
	DNSModeEffective model.DNSMode `json:"dns_mode_effective"`
	DNSModeFrom      string        `json:"dns_mode_from"`
}

type DeviceDetail struct {
	Device
	Addrs []store.DeviceAddr `json:"addrs"`
}

// DeviceEdit — правка: отсутствующее поле не меняется; пустой тип —
// вернуть угаданный, пустые режимы — по умолчанию и по профилю.
type DeviceEdit struct {
	Name    *string           `json:"name"`
	Type    *model.DeviceType `json:"type"`
	Note    *string           `json:"note"`
	DNSMode *model.DNSMode    `json:"dns_mode"`
	UPnP    *model.UPnPLevel  `json:"upnp"`
}

var (
	ErrNoDevice = errors.New("no such device")
	// ErrConfigured — режим DNS устройства задан в конфиге: правится там.
	ErrConfigured = errors.New("dns mode of this device is set in the config file")
)

type requestError struct{ error }

func (e requestError) Unwrap() error { return e.error }

// ErrBadRequest — ошибка в запросе (ответ 400).
func ErrBadRequest(err error) error { return requestError{err} }

func (s *Server) devicesOr503(w http.ResponseWriter) bool {
	if s.opts.Devices == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "device registry is not available"})
		return false
	}
	return true
}

func writeDeviceErr(w http.ResponseWriter, err error) {
	var br requestError
	switch {
	case errors.Is(err, ErrNoDevice):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
	case errors.Is(err, ErrConfigured):
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
	case errors.As(err, &br):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
}

func (s *Server) handleDevices(w http.ResponseWriter, _ *http.Request) {
	if s.devicesOr503(w) {
		writeJSON(w, http.StatusOK, map[string]any{"devices": s.opts.Devices.List()})
	}
}

func (s *Server) handleDevice(w http.ResponseWriter, r *http.Request) {
	if !s.devicesOr503(w) {
		return
	}
	d, err := s.opts.Devices.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeDeviceErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) handleDeviceUpdate(w http.ResponseWriter, r *http.Request) {
	if !s.devicesOr503(w) {
		return
	}
	var e DeviceEdit
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&e); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	d, err := s.opts.Devices.Update(r.Context(), r.PathValue("id"), e)
	if err != nil {
		writeDeviceErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

// handleDeviceMerge — POST /api/devices/{id}/merge {"from": "<id>"}: запись
// from вливается в {id}.
func (s *Server) handleDeviceMerge(w http.ResponseWriter, r *http.Request) {
	if !s.devicesOr503(w) {
		return
	}
	var req struct {
		From string `json:"from"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req); err != nil || req.From == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": `want {"from": "<device id>"}`})
		return
	}
	d, err := s.opts.Devices.Merge(r.Context(), r.PathValue("id"), req.From)
	if err != nil {
		writeDeviceErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) handleDeviceDismiss(w http.ResponseWriter, r *http.Request) {
	if !s.devicesOr503(w) {
		return
	}
	d, err := s.opts.Devices.Dismiss(r.Context(), r.PathValue("id"))
	if err != nil {
		writeDeviceErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) handleDeviceForget(w http.ResponseWriter, r *http.Request) {
	if !s.devicesOr503(w) {
		return
	}
	if err := s.opts.Devices.Forget(r.Context(), r.PathValue("id")); err != nil {
		writeDeviceErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"forgotten": r.PathValue("id")})
}
