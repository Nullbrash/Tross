package lists

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	corelists "tross/core/lists"
	"tross/core/model"
)

// fakeNet — источники по URL; счётчик загрузок; ETag — "v<версия>".
type fakeNet struct {
	mu      sync.Mutex
	body    map[string]string
	version map[string]int
	fail    map[string]error
	gets    map[string]int
	etags   []string
}

func newFakeNet() *fakeNet {
	return &fakeNet{body: map[string]string{}, version: map[string]int{}, fail: map[string]error{}, gets: map[string]int{}}
}

func (f *fakeNet) set(url, body string) {
	f.mu.Lock()
	f.body[url] = body
	f.version[url]++
	f.mu.Unlock()
}

func (f *fakeNet) fetch(_ context.Context, url, etag string) (Fetched, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets[url]++
	f.etags = append(f.etags, etag)
	if err := f.fail[url]; err != nil {
		return Fetched{}, err
	}
	tag := "v" + string(rune('0'+f.version[url]))
	if etag == tag {
		return Fetched{NotModified: true, ETag: etag}, nil
	}
	return Fetched{Body: io.NopCloser(strings.NewReader(f.body[url])), ETag: tag}, nil
}

func (f *fakeNet) count(url string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gets[url]
}

const srcURL = "https://lists.example/inside.lst"

func manager(t *testing.T, dir string, net *fakeNet, sources ...corelists.Source) (*Manager, *corelists.Rules) {
	t.Helper()
	if len(sources) == 0 {
		sources = []corelists.Source{{ID: "itdog", URL: srcURL, Format: corelists.FormatText, Purpose: corelists.PurposeBypass}}
	}
	rules := corelists.NewRules()
	opts := Options{Sources: sources, Interval: 24 * time.Hour, Dir: dir, Rules: rules, Retry: time.Hour,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if net != nil {
		opts.Fetch = net.fetch
	}
	return New(opts), rules
}

func bypass(r *corelists.Rules, d string) bool {
	got, ok := r.Lookup(d)
	return ok && got.Purpose == model.PurposeBypass
}

// Загрузка → правила и кеш; перезапуск без сети поднимает список из кеша.
func TestRefreshAndRestartFromCache(t *testing.T) {
	dir, net := t.TempDir(), newFakeNet()
	net.set(srcURL, "blocked.example\nother.example\n")
	m, rules := manager(t, dir, net)
	if err := m.Refresh(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if !bypass(rules, "www.blocked.example") {
		t.Fatal("list not applied")
	}
	if st := m.Sources()[0]; st.Domains != 2 || st.Error != "" || st.UpdatedAt.IsZero() {
		t.Errorf("status %+v", st)
	}
	m2, rules2 := manager(t, dir, nil)
	m2.LoadCache()
	if !bypass(rules2, "blocked.example") || m2.Sources()[0].Domains != 2 {
		t.Error("restart: cached list not loaded")
	}
	if err := m2.Refresh(context.Background(), ""); err == nil {
		t.Error("dry run must not download")
	}
}

// Битый или недоступный список — прежний действует, кеш не тронут.
func TestBrokenSourceKeepsOld(t *testing.T) {
	dir, net := t.TempDir(), newFakeNet()
	net.set(srcURL, "blocked.example\n")
	m, rules := manager(t, dir, net)
	_ = m.Refresh(context.Background(), "")
	net.set(srcURL, "# только комментарий\n")
	if err := m.Refresh(context.Background(), ""); err == nil {
		t.Error("empty list accepted")
	}
	net.mu.Lock()
	net.fail[srcURL] = errors.New("timeout")
	net.mu.Unlock()
	if err := m.Refresh(context.Background(), ""); err == nil {
		t.Error("failed download not reported")
	}
	if !bypass(rules, "blocked.example") || m.Sources()[0].Error == "" {
		t.Errorf("old rules must stay, error shown: %+v", m.Sources()[0])
	}
	m2, rules2 := manager(t, dir, nil)
	m2.LoadCache()
	if !bypass(rules2, "blocked.example") {
		t.Error("cache overwritten by a broken list")
	}
	// После сбоя — не раньше Retry.
	if m.due(m.opts.Sources[0], time.Now().Add(30*time.Minute)) {
		t.Error("retried within the retry pause")
	}
}

// Неизменившийся список не перекачивается: условный запрос по ETag.
func TestETagNotModified(t *testing.T) {
	net := newFakeNet()
	net.set(srcURL, "blocked.example\n")
	m, _ := manager(t, t.TempDir(), net)
	_ = m.Refresh(context.Background(), "")
	first := m.Sources()[0].UpdatedAt
	time.Sleep(10 * time.Millisecond)
	if err := m.Refresh(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if net.etags[1] != "v1" || !m.Sources()[0].UpdatedAt.After(first) || m.Sources()[0].Domains != 1 {
		t.Errorf("etags %v, status %+v", net.etags, m.Sources()[0])
	}
}

// Контрольная сумма не сменилась — большой файл не качается.
func TestChecksumSkipsDownload(t *testing.T) {
	net := newFakeNet()
	const big, sum = "https://lists.example/geosite.dat", "https://lists.example/geosite.dat.sha256sum"
	net.set(big, "inside.example\n")
	net.set(sum, "abc123  geosite.dat\n")
	src := corelists.Source{ID: "rf", URL: big, Checksum: sum, Format: corelists.FormatText, Purpose: corelists.PurposeInside}
	m, rules := manager(t, t.TempDir(), net, src)
	_ = m.Refresh(context.Background(), "")
	_ = m.Refresh(context.Background(), "")
	if net.count(big) != 1 || net.count(sum) != 2 {
		t.Errorf("downloads: file %d, checksum %d — want 1 and 2", net.count(big), net.count(sum))
	}
	if r, ok := rules.Lookup("inside.example"); !ok || r.Purpose != model.PurposeInside {
		t.Errorf("purpose from the source: %+v", r)
	}
	net.set(sum, "def456  geosite.dat\n")
	_ = m.Refresh(context.Background(), "")
	if net.count(big) != 2 {
		t.Error("changed checksum must download the file")
	}
}

func TestDisabledAndTooLarge(t *testing.T) {
	net := newFakeNet()
	net.set(srcURL, strings.Repeat("a.example\n", 100))
	off := corelists.Source{ID: "off", URL: "https://lists.example/off.lst", Format: corelists.FormatText, Purpose: corelists.PurposeBypass, Disabled: true}
	on := corelists.Source{ID: "on", URL: srcURL, Format: corelists.FormatText, Purpose: corelists.PurposeBypass}
	m, _ := manager(t, t.TempDir(), net, off, on)
	m.opts.MaxBytes = 100
	if err := m.Refresh(context.Background(), "off"); err == nil {
		t.Error("disabled source refreshed")
	}
	if err := m.Refresh(context.Background(), "on"); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Errorf("size limit: %v", err)
	}
	if len(m.Sources()) != 2 {
		t.Error("disabled source must still be listed")
	}
}

// Класс из списков не прячется за более важным правилом обхода.
func TestClassRule(t *testing.T) {
	r := corelists.NewRules()
	_ = r.SetManual([]model.DomainRule{{Pattern: "video.example", Match: model.MatchSuffix, Purpose: model.PurposeBypass}})
	_ = r.SetOnline("cls", []model.DomainRule{{Pattern: "video.example", Match: model.MatchSuffix, Purpose: model.PurposeClass, Class: model.ClassStreaming}})
	got, ok := ClassRule(r)("www.video.example")
	if !ok || got.Class != model.ClassStreaming {
		t.Errorf("class rule %+v %v", got, ok)
	}
	if _, ok := ClassRule(r)("none.example"); ok {
		t.Error("no class rule expected")
	}
}
