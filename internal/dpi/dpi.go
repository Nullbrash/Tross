// Package dpi — движок обхода DPI (nfqws2, zapret2): экземпляр на канал со
// своей очередью NFQUEUE, стратегией и hostlist; проверка стратегии до
// применения, сторож процессов, откат на прежнюю стратегию. Решения «какие
// домены и какой стратегией» — core/dpi и демон.
package dpi

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	coredpi "tross/core/dpi"
	"tross/core/model"
)

// Engine — установленный движок и рабочий каталог (hostlist-файлы).
type Engine struct {
	Binary string
	LuaDir string
	Dir    string
	// Debug — подробный журнал движка в Dir/<канал>.debug.log (разбор
	// поломок; растёт быстро — только на время).
	Debug bool
}

// luaLibs — библиотеки движка, без которых функции стратегий не определены.
var luaLibs = []string{"zapret-lib.lua", "zapret-antidpi.lua", "zapret-auto.lua"}

// LinkConfig — канал и его очередь. DPIMark — бит «пакет движка»
// (dataplane.DPIMark): только он, без битов канала — движок считает своим
// любой пакет, у которого есть хоть один бит его метки. Свои пакеты он
// метит меткой исходного пакета (канал, класс, корзина) с этим битом — ip
// rule ведёт их в канал соединения.
type LinkConfig struct {
	Link    model.LinkID
	Queue   uint16
	DPIMark uint32
}

func (e Engine) libArgs() []string {
	var out []string
	for _, l := range luaLibs {
		out = append(out, "--lua-init=@"+filepath.Join(e.LuaDir, l))
	}
	return out
}

// HostlistPath — файл доменов канала.
func (e Engine) HostlistPath(link model.LinkID) string {
	return filepath.Join(e.Dir, string(link)+".hosts")
}

// Args — полный запуск экземпляра канала: один профиль — TLS на 443 по
// hostlist; всё, что не совпало, движок пропускает нетронутым.
func (e Engine) Args(lc LinkConfig, s coredpi.Strategy) []string {
	// --bind-fix4: свои пакеты — через интерфейс исходного (при policy
	// routing ядро может выбрать не тот).
	out := []string{fmt.Sprintf("--qnum=%d", lc.Queue), fmt.Sprintf("--fwmark=%#x", lc.DPIMark), "--bind-fix4"}
	if e.Debug {
		out = append(out, "--debug=@"+filepath.Join(e.Dir, string(lc.Link)+".debug.log"))
	}
	out = append(out, e.libArgs()...)
	out = append(out, "--filter-tcp=443", "--filter-l7=tls", "--hostlist="+e.HostlistPath(lc.Link), "--out-range=-d10")
	return append(out, s.Args()...)
}

// Runner — запуск программ (подменяется в тестах).
type Runner interface {
	// Output — короткий запуск: вывод и ошибка (код возврата ≠ 0 — ошибка).
	Output(ctx context.Context, bin string, args []string) ([]byte, error)
	// Start — долгий запуск; вывод — в out.
	Start(bin string, args []string, out io.Writer) (Process, error)
}

type Process interface {
	Wait() error
	Stop() error
}

var blobRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// checkCode — Lua-проверка, что функции шагов и заготовки (blob) есть:
// --dry-run движка проверяет только синтаксис параметров и принимает
// несуществующую функцию.
func checkCode(s coredpi.Strategy) (string, error) {
	var b strings.Builder
	for _, st := range s.Steps {
		parts := strings.Split(st, ":")
		fmt.Fprintf(&b, "assert(type(%s)==\"function\",\"no function %s\");", parts[0], parts[0])
		for _, p := range parts[1:] {
			k, v, _ := strings.Cut(p, "=")
			if k != "blob" || strings.HasPrefix(v, "0x") {
				continue
			}
			if !blobRe.MatchString(v) {
				return "", fmt.Errorf("blob %q: want a name or 0xHEX", v)
			}
			fmt.Fprintf(&b, "assert(_G[%q]~=nil,\"no blob %s\");", v, v)
		}
	}
	return b.String(), nil
}

// Validate — стратегия, которую движок примет и выполнит: форма, пробный
// разбор параметров, наличие функций и заготовок.
func (e Engine) Validate(ctx context.Context, r Runner, lc LinkConfig, s coredpi.Strategy) error {
	if err := s.Validate(); err != nil {
		return err
	}
	code, err := checkCode(s)
	if err != nil {
		return err
	}
	if out, err := r.Output(ctx, e.Binary, append([]string{"--dry-run"}, e.Args(lc, s)...)); err != nil {
		return fmt.Errorf("dry-run: %v: %s", err, lastLines(out, 3))
	}
	args := append([]string{"--intercept=0"}, e.libArgs()...)
	if out, err := r.Output(ctx, e.Binary, append(args, "--lua-init="+code)); err != nil {
		return fmt.Errorf("lua check: %v: %s", err, lastLines(out, 3))
	}
	return nil
}

func lastLines(b []byte, n int) string {
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	return strings.Join(lines[max(0, len(lines)-n):], " | ")
}

// WriteHostlist — атомарно (временный файл и rename): движок перечитывает
// файл по смене времени изменения и не должен увидеть его наполовину.
func (e Engine) WriteHostlist(link model.LinkID, domains []string) error {
	// Движок перечитывает файл после сброса прав root — каталог и файл
	// доступны на чтение всем.
	if err := os.MkdirAll(e.Dir, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(e.Dir, 0o755); err != nil {
		return err
	}
	path := e.HostlistPath(link)
	tmp, err := os.CreateTemp(e.Dir, ".hosts-*")
	if err != nil {
		return err
	}
	var b bytes.Buffer
	for _, d := range domains {
		b.WriteString(d)
		b.WriteByte('\n')
	}
	if _, err := tmp.Write(b.Bytes()); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// State — состояние экземпляра канала.
type State string

const (
	// StateIdle — нечего делать: нет стратегии или доменов.
	StateIdle    State = "idle"
	StateRunning State = "running"
	// StateFailed — упал и ждёт перезапуска.
	StateFailed State = "failed"
)

// LinkStatus — для API.
type LinkStatus struct {
	Link     model.LinkID `json:"link"`
	State    State        `json:"state"`
	Strategy string       `json:"strategy,omitempty"`
	Domains  int          `json:"domains"`
	Restarts int          `json:"restarts"`
	Since    time.Time    `json:"since,omitzero"`
	LastErr  string       `json:"last_error,omitempty"`
}

// Event — что сообщить демону (журнал, события).
type Event struct {
	Link model.LinkID
	Msg  string
}

// Manager — экземпляры движка по каналам.
type Manager struct {
	eng    Engine
	run    Runner
	events func(Event)

	mu    sync.Mutex
	links map[model.LinkID]*inst
	exits chan exitMsg
}

type inst struct {
	cfg      LinkConfig
	want     *coredpi.Strategy
	prev     *coredpi.Strategy
	domains  []string
	proc     Process
	gen      int
	state    State
	since    time.Time
	restarts int
	backoff  time.Duration
	retryAt  time.Time
	lastErr  string
}

type exitMsg struct {
	link model.LinkID
	gen  int
	err  error
}

// Пределы сторожа: упавший сразу после смены стратегии — откат на прежнюю;
// перезапуски — с растущей паузой.
const (
	quickCrash = 5 * time.Second
	backoffMin = time.Second
	backoffMax = time.Minute
)

func NewManager(eng Engine, run Runner, links []LinkConfig, events func(Event)) *Manager {
	m := &Manager{eng: eng, run: run, events: events, links: map[model.LinkID]*inst{}, exits: make(chan exitMsg, 16)}
	for _, lc := range links {
		m.links[lc.Link] = &inst{cfg: lc, state: StateIdle}
	}
	return m
}

func (m *Manager) emit(link model.LinkID, format string, args ...any) {
	if m.events != nil {
		m.events(Event{Link: link, Msg: fmt.Sprintf(format, args...)})
	}
}

// Apply — стратегия и домены канала. Новая стратегия проверяется до
// применения: не прошла — остаётся прежняя. Изменились только домены —
// движок не перезапускается (перечитает файл сам).
func (m *Manager) Apply(ctx context.Context, link model.LinkID, s *coredpi.Strategy, domains []string) error {
	m.mu.Lock()
	in, ok := m.links[link]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("dpi: link %s has no engine", link)
	}
	domains = slices.Clone(domains)
	slices.Sort(domains)
	domains = slices.Compact(domains)
	// Файл доменов — до проверки: пробный запуск читает его.
	if err := m.eng.WriteHostlist(link, domains); err != nil {
		return err
	}
	m.mu.Lock()
	newStrategy := !sameStrategy(in.want, s)
	m.mu.Unlock()
	if s != nil && newStrategy {
		if err := m.eng.Validate(ctx, m.run, in.cfg, *s); err != nil {
			m.emit(link, "strategy %s rejected: %v", s.ID, err)
			return err
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	changed := !sameStrategy(in.want, s)
	if changed {
		in.prev, in.want = in.want, s
	}
	in.domains = domains
	if changed || (in.proc == nil) != (in.want == nil || len(domains) == 0) {
		m.restartLocked(in, "strategy or domains changed")
	}
	return nil
}

func sameStrategy(a, b *coredpi.Strategy) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.ID == b.ID && slices.Equal(a.Args(), b.Args())
}

// restartLocked — остановить и, если есть что делать, запустить заново.
func (m *Manager) restartLocked(in *inst, why string) {
	if in.proc != nil {
		in.gen++ // выход остановленного процесса — не авария
		_ = in.proc.Stop()
		in.proc = nil
	}
	in.state, in.since = StateIdle, time.Time{}
	if in.want == nil || len(in.domains) == 0 {
		return
	}
	m.startLocked(in, why)
}

func (m *Manager) startLocked(in *inst, why string) {
	w := &lineLog{in: in, m: m}
	p, err := m.run.Start(m.eng.Binary, m.eng.Args(in.cfg, *in.want), w)
	in.gen++
	if err != nil {
		in.state, in.lastErr = StateFailed, err.Error()
		m.scheduleLocked(in)
		m.emit(in.cfg.Link, "engine not started: %v", err)
		return
	}
	in.proc, in.state, in.since = p, StateRunning, time.Now()
	m.emit(in.cfg.Link, "engine started, strategy %s (%s)", in.want.ID, why)
	gen, link := in.gen, in.cfg.Link
	go func() { m.exits <- exitMsg{link: link, gen: gen, err: p.Wait()} }()
}

func (m *Manager) scheduleLocked(in *inst) {
	in.backoff = min(max(in.backoff*2, backoffMin), backoffMax)
	in.retryAt = time.Now().Add(in.backoff)
}

// Run — сторож до отмены ctx: упавший экземпляр перезапускается с растущей
// паузой; упавший сразу после смены стратегии — откат на прежнюю. При
// отмене экземпляры останавливаются (очередь с bypass пропускает трафик).
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			m.stopAll()
			return
		case e := <-m.exits:
			m.onExit(e)
		case <-t.C:
			m.retry()
		}
	}
}

func (m *Manager) onExit(e exitMsg) {
	m.mu.Lock()
	defer m.mu.Unlock()
	in := m.links[e.link]
	if in == nil || e.gen != in.gen {
		return
	}
	lived := time.Since(in.since)
	in.proc, in.state, in.restarts = nil, StateFailed, in.restarts+1
	if e.err != nil && in.lastErr == "" {
		in.lastErr = e.err.Error()
	}
	if lived < quickCrash && in.prev != nil {
		m.emit(e.link, "engine exited %v after start with strategy %s — back to %s", lived.Round(time.Millisecond), in.want.ID, in.prev.ID)
		in.want, in.prev = in.prev, nil
		in.backoff = 0
	} else {
		m.emit(e.link, "engine exited after %v: %v", lived.Round(time.Second), e.err)
		if lived > backoffMax {
			in.backoff = 0
		}
	}
	m.scheduleLocked(in)
}

func (m *Manager) retry() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, in := range m.links {
		if in.state == StateFailed && in.proc == nil && time.Now().After(in.retryAt) && in.want != nil && len(in.domains) > 0 {
			m.startLocked(in, "restart")
		}
	}
}

func (m *Manager) stopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, in := range m.links {
		if in.proc != nil {
			in.gen++
			_ = in.proc.Stop()
			in.proc, in.state = nil, StateIdle
		}
	}
}

// Status — экземпляры по каналам.
func (m *Manager) Status() []LinkStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []LinkStatus
	for _, in := range m.links {
		st := LinkStatus{Link: in.cfg.Link, State: in.state, Domains: len(in.domains), Restarts: in.restarts, Since: in.since, LastErr: in.lastErr}
		if in.want != nil {
			st.Strategy = in.want.ID
		}
		out = append(out, st)
	}
	slices.SortFunc(out, func(a, b LinkStatus) int { return strings.Compare(string(a.Link), string(b.Link)) })
	return out
}

// lineLog — вывод движка: ошибки Lua не роняют процесс, но профиль молча не
// работает — запоминаются как последняя ошибка.
type lineLog struct {
	in  *inst
	m   *Manager
	buf []byte
}

func (w *lineLog) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		line := strings.TrimSpace(string(w.buf[:i]))
		w.buf = w.buf[i+1:]
		if strings.Contains(line, "LUA ERROR") {
			w.m.mu.Lock()
			w.in.lastErr = line
			w.m.mu.Unlock()
			w.m.emit(w.in.cfg.Link, "engine: %s", line)
		}
	}
	return len(p), nil
}

// ErrNoEngine — движок не установлен или версии не совпадают.
var ErrNoEngine = errors.New("dpi: engine not installed")

// CheckInstall — движок на месте и той версии, что в конфиге (файл
// VERSION рядом с движком: у самостоятельной сборки движок номер выпуска
// не печатает).
func (e Engine) CheckInstall(version string) error {
	if _, err := os.Stat(e.Binary); err != nil {
		return fmt.Errorf("%w: %v", ErrNoEngine, err)
	}
	for _, l := range luaLibs {
		if _, err := os.Stat(filepath.Join(e.LuaDir, l)); err != nil {
			return fmt.Errorf("%w: %v", ErrNoEngine, err)
		}
	}
	if version == "" {
		return nil
	}
	f, err := os.Open(filepath.Join(filepath.Dir(e.Binary), "VERSION"))
	if err != nil {
		return fmt.Errorf("%w: version file: %v", ErrNoEngine, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() || strings.TrimSpace(sc.Text()) != version {
		return fmt.Errorf("%w: version %q, want %q", ErrNoEngine, strings.TrimSpace(sc.Text()), version)
	}
	return nil
}
