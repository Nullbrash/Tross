package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"tross/core/model"
)

type fakeDevices struct {
	devs   map[string]Device
	merged [2]string
}

func (f *fakeDevices) List() []Device {
	var out []Device
	for _, d := range f.devs {
		out = append(out, d)
	}
	return out
}

func (f *fakeDevices) Get(_ context.Context, id string) (DeviceDetail, error) {
	d, ok := f.devs[id]
	if !ok {
		return DeviceDetail{}, ErrNoDevice
	}
	return DeviceDetail{Device: d}, nil
}

func (f *fakeDevices) Update(_ context.Context, id string, e DeviceEdit) (Device, error) {
	d, ok := f.devs[id]
	switch {
	case !ok:
		return Device{}, ErrNoDevice
	case e.DNSMode != nil:
		return Device{}, ErrConfigured
	case e.Type != nil && !e.Type.Valid():
		return Device{}, ErrBadRequest(errors.New("invalid type"))
	}
	if e.Name != nil {
		d.Name = *e.Name
	}
	f.devs[id] = d
	return d, nil
}

func (f *fakeDevices) Merge(_ context.Context, dst, src string) (Device, error) {
	f.merged = [2]string{dst, src}
	return f.devs[dst], nil
}

func (f *fakeDevices) Dismiss(_ context.Context, id string) (Device, error) { return f.devs[id], nil }

func (f *fakeDevices) Forget(_ context.Context, id string) error {
	if _, ok := f.devs[id]; !ok {
		return ErrNoDevice
	}
	delete(f.devs, id)
	return nil
}

func devicesServer(f *fakeDevices) http.Handler {
	return New(Options{NoAuth: true,
		Log:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		Devices:         f,
		AllowedNetworks: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
	}).Handler()
}

func call(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:5000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestDevicesAPI(t *testing.T) {
	f := &fakeDevices{devs: map[string]Device{"dev-a60000000001": {Device: model.Device{ID: "dev-a60000000001", Type: model.DeviceTypePhone}, Online: true}}}
	h := devicesServer(f)

	rec := call(h, "GET", "/api/devices", "")
	var list struct{ Devices []Device }
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &list) != nil || len(list.Devices) != 1 || !list.Devices[0].Online {
		t.Fatalf("list %d %s", rec.Code, rec.Body)
	}
	if rec := call(h, "GET", "/api/devices/dev-a60000000001", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"addrs"`) {
		t.Errorf("get %d %s", rec.Code, rec.Body)
	}
	for _, c := range []struct {
		method, path, body string
		code               int
	}{
		{"GET", "/api/devices/dev-missing", "", 404},
		{"PATCH", "/api/devices/dev-a60000000001", `{"name":"Телефон"}`, 200},
		{"PATCH", "/api/devices/dev-a60000000001", `{"dns_mode":"block"}`, 409},
		{"PATCH", "/api/devices/dev-a60000000001", `{"type":"fridge"}`, 400},
		{"PATCH", "/api/devices/dev-a60000000001", `not json`, 400},
		{"PATCH", "/api/devices/dev-missing", `{}`, 404},
		{"POST", "/api/devices/dev-a60000000001/merge", `{}`, 400},
		{"POST", "/api/devices/dev-a60000000001/merge", `{"from":"dev-da0000000002"}`, 200},
		{"POST", "/api/devices/dev-a60000000001/dismiss", ``, 200},
		{"DELETE", "/api/devices/dev-missing", ``, 404},
		{"DELETE", "/api/devices/dev-a60000000001", ``, 200},
	} {
		if rec := call(h, c.method, c.path, c.body); rec.Code != c.code {
			t.Errorf("%s %s %s: %d %s, want %d", c.method, c.path, c.body, rec.Code, rec.Body, c.code)
		}
	}
	if f.merged != [2]string{"dev-a60000000001", "dev-da0000000002"} {
		t.Errorf("merge direction %v", f.merged)
	}
	// Без реестра — 503, а не падение.
	none := New(Options{NoAuth: true, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), AllowedNetworks: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}).Handler()
	if rec := call(none, "GET", "/api/devices", ""); rec.Code != 503 {
		t.Errorf("no registry: %d", rec.Code)
	}
}
