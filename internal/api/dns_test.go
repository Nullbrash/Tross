package api

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	corelists "tross/core/lists"
	"tross/core/model"
)

type fakeLists struct {
	manual    []model.DomainRule
	refreshed string
}

func (f *fakeLists) Sources() []corelists.SourceStatus { return []corelists.SourceStatus{{Domains: 7}} }
func (f *fakeLists) Refresh(_ context.Context, id string) error {
	f.refreshed = id
	return nil
}
func (f *fakeLists) Manual() []model.DomainRule { return f.manual }
func (f *fakeLists) AddManual(_ context.Context, r ManualRule) error {
	f.manual = append(f.manual, model.DomainRule{Pattern: r.Domain, Purpose: r.Purpose})
	return nil
}
func (f *fakeLists) DeleteManual(context.Context, string, model.MatchKind) error { return ErrNotFound }

func dnsServer(dns func(context.Context) DNSStatus, l Lists) http.Handler {
	return New(Options{
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), DNS: dns, Lists: l,
		AllowedNetworks: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
	}).Handler()
}

func send(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:5000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestDNSAndListsAPI(t *testing.T) {
	if rec := send(dnsServer(nil, nil), http.MethodGet, "/api/dns", ""); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("no resolver: %d", rec.Code)
	}
	l := &fakeLists{}
	h := dnsServer(func(context.Context) DNSStatus { return DNSStatus{Queries: 5, Serving: "resolver"} }, l)
	if rec := send(h, http.MethodGet, "/api/dns", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"serving":"resolver"`) {
		t.Errorf("dns: %d %s", rec.Code, rec.Body)
	}
	if rec := send(h, http.MethodGet, "/api/lists", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"domains":7`) {
		t.Errorf("lists: %d %s", rec.Code, rec.Body)
	}
	if rec := send(h, http.MethodPost, "/api/lists/refresh?source=itdog", ""); rec.Code != http.StatusOK || l.refreshed != "itdog" {
		t.Errorf("refresh: %d %q", rec.Code, l.refreshed)
	}
	if rec := send(h, http.MethodPost, "/api/lists/manual", `{"domain":"a.example","purpose":"bypass"}`); rec.Code != http.StatusOK || len(l.manual) != 1 {
		t.Errorf("add: %d %s", rec.Code, rec.Body)
	}
	if rec := send(h, http.MethodPost, "/api/lists/manual", `{bad`); rec.Code != http.StatusBadRequest {
		t.Errorf("bad json: %d", rec.Code)
	}
	if rec := send(h, http.MethodDelete, "/api/lists/manual?domain=cfg.example", ""); rec.Code != http.StatusNotFound {
		t.Errorf("delete config rule: %d", rec.Code)
	}
}
