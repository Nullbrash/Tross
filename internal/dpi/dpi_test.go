package dpi

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	coredpi "tross/core/dpi"
)

// fakeRunner — движок без движка: проверки отвечают по правилам теста,
// процессы живут, пока их не остановят или не «уронят».
type fakeRunner struct {
	mu      sync.Mutex
	starts  [][]string
	procs   []*fakeProc
	badFunc string // проверка Lua отвергает стратегию с этой функцией
	crash   string // процесс со стратегией, содержащей это, падает сразу
}

func (f *fakeRunner) Output(_ context.Context, _ string, args []string) ([]byte, error) {
	for _, a := range args {
		if f.badFunc != "" && strings.HasPrefix(a, "--lua-init=assert") && strings.Contains(a, "no function "+f.badFunc) {
			return []byte("LUA ERROR: no function " + f.badFunc), errors.New("exit status 1")
		}
	}
	return nil, nil
}

func (f *fakeRunner) Start(_ string, args []string, out io.Writer) (Process, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := &fakeProc{done: make(chan struct{}), out: out}
	f.starts = append(f.starts, args)
	f.procs = append(f.procs, p)
	if f.crash != "" && strings.Contains(strings.Join(args, " "), f.crash) {
		p.exit(errors.New("exit status 1"))
	}
	return p, nil
}

func (f *fakeRunner) last() (*fakeProc, []string, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.procs) == 0 {
		return nil, nil, 0
	}
	return f.procs[len(f.procs)-1], f.starts[len(f.starts)-1], len(f.starts)
}

type fakeProc struct {
	done chan struct{}
	once sync.Once
	err  error
	out  io.Writer
}

func (p *fakeProc) exit(err error) { p.once.Do(func() { p.err = err; close(p.done) }) }
func (p *fakeProc) Wait() error    { <-p.done; return p.err }
func (p *fakeProc) Stop() error    { p.exit(nil); return nil }

func strat(id string, steps ...string) *coredpi.Strategy {
	return &coredpi.Strategy{ID: id, Payload: "tls_client_hello", Steps: steps}
}

func bench(t *testing.T) (*Manager, *fakeRunner, Engine, *[]string) {
	t.Helper()
	eng := Engine{Binary: "/opt/zapret2/nfqws2", LuaDir: "/opt/zapret2/lua", Dir: t.TempDir()}
	run := &fakeRunner{}
	var mu sync.Mutex
	var events []string
	m := NewManager(eng, run, []LinkConfig{{Link: "isp1", Queue: 200, DPIMark: 0x40000000}}, func(e Event) {
		mu.Lock()
		events = append(events, string(e.Link)+": "+e.Msg)
		mu.Unlock()
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return m, run, eng, &events
}

func until(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not reached", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestArgs(t *testing.T) {
	eng := Engine{Binary: "/b/nfqws2", LuaDir: "/b/lua", Dir: "/var/lib/tross/dpi"}
	got := strings.Join(eng.Args(LinkConfig{Link: "isp1", Queue: 201, DPIMark: 0x40000000}, *strat("s", "fake:blob=fake_default_tls:tcp_md5", "multisplit:pos=1,midsld")), " ")
	want := "--qnum=201 --fwmark=0x40000000 --bind-fix4 --lua-init=@" + filepath.Join("/b/lua", "zapret-lib.lua") +
		" --lua-init=@" + filepath.Join("/b/lua", "zapret-antidpi.lua") + " --lua-init=@" + filepath.Join("/b/lua", "zapret-auto.lua") +
		" --filter-tcp=443 --filter-l7=tls --hostlist=" + filepath.Join("/var/lib/tross/dpi", "isp1.hosts") +
		" --out-range=-d10 --payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:tcp_md5 --lua-desync=multisplit:pos=1,midsld"
	if got != want {
		t.Errorf("args:\n got %s\nwant %s", got, want)
	}
}

func TestCheckCode(t *testing.T) {
	code, err := checkCode(*strat("s", "fake:blob=fake_default_tls:tcp_md5", "fake:blob=0x1603", "multisplit:pos=1"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`assert(type(fake)=="function"`, `assert(type(multisplit)=="function"`, `assert(_G["fake_default_tls"]~=nil`} {
		if !strings.Contains(code, want) {
			t.Errorf("code lacks %s: %s", want, code)
		}
	}
	if strings.Contains(code, "0x1603") {
		t.Error("hex blob checked as a name")
	}
	if _, err := checkCode(*strat("s", "fake:blob=a.b")); err == nil {
		t.Error("odd blob name accepted")
	}
}

// Новая стратегия проверяется до применения; отвергнутая не заменяет
// рабочую.
func TestApplyValidatesAndKeepsWorking(t *testing.T) {
	m, run, eng, _ := bench(t)
	ctx := context.Background()
	if err := m.Apply(ctx, "isp1", strat("good", "multisplit:pos=1,midsld"), []string{"b.example", "a.example", "a.example"}); err != nil {
		t.Fatal(err)
	}
	_, args, n := run.last()
	if n != 1 || !strings.Contains(strings.Join(args, " "), "multisplit:pos=1,midsld") {
		t.Fatalf("starts %d, args %v", n, args)
	}
	b, _ := os.ReadFile(eng.HostlistPath("isp1"))
	if string(b) != "a.example\nb.example\n" {
		t.Errorf("hostlist %q", b)
	}
	run.badFunc = "nosuch"
	if err := m.Apply(ctx, "isp1", strat("bad", "nosuch:x=1"), []string{"a.example"}); err == nil {
		t.Fatal("strategy with a missing function accepted")
	}
	if _, _, n := run.last(); n != 1 || m.Status()[0].Strategy != "good" {
		t.Errorf("rejected strategy touched the engine: starts %d, status %+v", n, m.Status())
	}
	// Только домены — без перезапуска.
	if err := m.Apply(ctx, "isp1", strat("good", "multisplit:pos=1,midsld"), []string{"c.example"}); err != nil {
		t.Fatal(err)
	}
	if _, _, n := run.last(); n != 1 {
		t.Errorf("domains change restarted the engine: %d starts", n)
	}
	// Нет доменов — движок не нужен.
	_ = m.Apply(ctx, "isp1", strat("good", "multisplit:pos=1,midsld"), nil)
	if st := m.Status()[0]; st.State != StateIdle {
		t.Errorf("no domains, state %s", st.State)
	}
	if err := m.Apply(ctx, "lte", strat("good", "multisplit:pos=1"), []string{"a.example"}); err == nil {
		t.Error("link without engine accepted")
	}
}

// Упал — перезапуск; упал сразу после смены стратегии — откат на прежнюю.
func TestCrashRestartAndRollback(t *testing.T) {
	m, run, _, events := bench(t)
	ctx := context.Background()
	_ = m.Apply(ctx, "isp1", strat("old", "multisplit:pos=1,midsld"), []string{"a.example"})
	p, _, _ := run.last()
	// Долго проработал и упал — перезапуск той же стратегией.
	m.mu.Lock()
	m.links["isp1"].since = time.Now().Add(-time.Hour)
	m.mu.Unlock()
	p.exit(errors.New("killed"))
	until(t, "restart", func() bool { _, _, n := run.last(); return n == 2 })
	if st := m.Status()[0]; st.Strategy != "old" || st.Restarts != 1 {
		t.Errorf("after restart: %+v", st)
	}
	run.crash = "multidisorder"
	_ = m.Apply(ctx, "isp1", strat("new", "multidisorder:pos=1,midsld"), []string{"a.example"})
	until(t, "rollback", func() bool {
		_, args, _ := run.last()
		return m.Status()[0].Strategy == "old" && m.Status()[0].State == StateRunning && strings.Contains(strings.Join(args, " "), "multisplit")
	})
	if !strings.Contains(strings.Join(*events, "\n"), "back to old") {
		t.Errorf("no rollback event: %v", *events)
	}
}

func TestLuaErrorRemembered(t *testing.T) {
	m, run, _, _ := bench(t)
	_ = m.Apply(context.Background(), "isp1", strat("s", "multisplit:pos=1"), []string{"a.example"})
	p, _, _ := run.last()
	_, _ = io.WriteString(p.out, "starting\nLUA ERROR: attempt to call nil\npart")
	until(t, "lua error", func() bool { return strings.Contains(m.Status()[0].LastErr, "LUA ERROR") })
}

func TestCheckInstall(t *testing.T) {
	dir := t.TempDir()
	eng := Engine{Binary: filepath.Join(dir, "nfqws2"), LuaDir: filepath.Join(dir, "lua")}
	if !errors.Is(eng.CheckInstall("v1"), ErrNoEngine) {
		t.Fatal("missing binary accepted")
	}
	_ = os.WriteFile(eng.Binary, nil, 0o755)
	_ = os.MkdirAll(eng.LuaDir, 0o755)
	for _, l := range luaLibs {
		_ = os.WriteFile(filepath.Join(eng.LuaDir, l), nil, 0o644)
	}
	_ = os.WriteFile(filepath.Join(dir, "VERSION"), []byte("v1.0.5.2\n"), 0o644)
	if err := eng.CheckInstall("v1.0.5.2"); err != nil {
		t.Error(err)
	}
	if !errors.Is(eng.CheckInstall("v1.0.6"), ErrNoEngine) {
		t.Error("wrong version accepted")
	}
}
