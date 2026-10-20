package dpi

import (
	"slices"
	"strings"
	"testing"
	"time"

	"tross/core/model"
)

func TestBuiltinCatalog(t *testing.T) {
	c, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	if c.Engine == "" || len(c.Strategies) < 6 {
		t.Fatalf("catalog: engine %q, %d strategies", c.Engine, len(c.Strategies))
	}
	safe := c.Candidates()
	for _, s := range safe {
		if len(s.Risks()) != 0 {
			t.Errorf("%s: risky %v among default candidates", s.ID, s.Risks())
		}
	}
	if len(safe) == len(c.Strategies) {
		t.Error("risky strategies are not filtered out")
	}
	withTS := c.Candidates(RiskTS)
	if len(withTS) <= len(safe) || slices.ContainsFunc(withTS, func(s Strategy) bool { return slices.Contains(s.Risks(), RiskSYN) }) {
		t.Errorf("allow ts: %d candidates (safe %d), syn must stay out", len(withTS), len(safe))
	}
	s, ok := c.ByID("fake-md5-split")
	if !ok {
		t.Fatal("fake-md5-split missing")
	}
	if got := strings.Join(s.Args(), " "); got != "--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:tcp_md5 --lua-desync=multisplit:pos=1,midsld" {
		t.Errorf("args: %s", got)
	}
}

func TestStrategyRisksAndValidate(t *testing.T) {
	cases := []struct {
		steps []string
		risks []Risk
	}{
		{[]string{"multisplit:pos=1,midsld"}, nil},
		{[]string{"fake:tcp_ts=-600000"}, []Risk{RiskTS}},
		{[]string{"fakedsplit:pos=midsld:tcp_ack=-66000:tcp_ts_up"}, []Risk{RiskTS}},
		{[]string{"syndata:blob=tls_google", "wssize:wsize=1:scale=6"}, []Risk{RiskSYN}},
		{[]string{"fake:tcp_ts=-1", "wssize:wsize=1"}, []Risk{RiskSYN, RiskTS}},
	}
	for _, c := range cases {
		if got := (Strategy{Steps: c.steps}).Risks(); !slices.Equal(got, c.risks) {
			t.Errorf("%v: risks %v, want %v", c.steps, got, c.risks)
		}
	}
	bad := []Strategy{
		{ID: "Bad ID", Payload: "tls_client_hello", Steps: []string{"multisplit:pos=1"}},
		{ID: "x", Steps: []string{"multisplit:pos=1"}},
		{ID: "x", Payload: "tls_client_hello"},
		{ID: "x", Payload: "tls_client_hello", Steps: []string{"multisplit pos=1"}},
		{ID: "x", Payload: "tls_client_hello", Steps: []string{"luaexec:code=os.execute('x')"}},
		{ID: "x", Payload: "tls_client_hello", Steps: []string{"luaexec:code=x"}},
	}
	for _, s := range bad {
		if s.Validate() == nil {
			t.Errorf("%+v accepted", s)
		}
	}
	if _, err := ParseCatalog([]byte("engine: z\nstrategies:\n  - {id: a, payload: p, steps: [x]}\n  - {id: a, payload: p, steps: [y]}\n")); err == nil {
		t.Error("duplicate id accepted")
	}
	if _, err := ParseCatalog([]byte("engine: z\nextra: 1\n")); err == nil {
		t.Error("unknown field accepted")
	}
}

var (
	okCtl  = Attempt{Connect: OK, Handshake: OK, Received: 1 << 20, Complete: true, Elapsed: time.Second}
	opened = Attempt{Connect: OK, Handshake: OK, Received: 1 << 20, Complete: true, Elapsed: time.Second}
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name            string
		direct, control Attempt
		want            BlockKind
	}{
		{"opens", opened, okCtl, KindNone},
		{"control down too", Attempt{Connect: Timeout}, Attempt{Connect: Timeout}, KindLinkBad},
		{"control tls fails", opened, Attempt{Connect: OK, Handshake: Reset}, KindLinkBad},
		{"no tcp", Attempt{Connect: Timeout}, okCtl, KindIP},
		{"tcp reset", Attempt{Connect: Reset}, okCtl, KindIP},
		{"reset after hello", Attempt{Connect: OK, Handshake: Reset}, okCtl, KindSNI},
		{"silence after hello", Attempt{Connect: OK, Handshake: Timeout}, okCtl, KindSNI},
		{"wrong server", Attempt{Connect: OK, Handshake: BadCert}, okCtl, KindIntercepted},
		{"stalls at 20 KB", Attempt{Connect: OK, Handshake: OK, Received: 20 << 10}, okCtl, KindFreeze},
		{"stalls with nothing", Attempt{Connect: OK, Handshake: OK}, okCtl, KindSNI},
		{"stalls late", Attempt{Connect: OK, Handshake: OK, Received: 5 << 20}, okCtl, KindSNI},
		{"slow", Attempt{Connect: OK, Handshake: OK, Received: 1 << 20, Complete: true, Elapsed: 10 * time.Second}, okCtl, KindThrottle},
		{"a bit slower", Attempt{Connect: OK, Handshake: OK, Received: 1 << 20, Complete: true, Elapsed: 3 * time.Second}, okCtl, KindNone},
		{"small and slow is not throttle", Attempt{Connect: OK, Handshake: OK, Received: 10 << 10, Complete: true, Elapsed: 5 * time.Second}, okCtl, KindNone},
	}
	for _, c := range cases {
		if got := Classify(c.direct, c.control); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
	for k, want := range map[BlockKind]bool{KindSNI: true, KindFreeze: true, KindThrottle: true, KindIntercepted: true, KindIP: false, KindNone: false, KindLinkBad: false} {
		if k.Helps() != want {
			t.Errorf("%s helps = %v", k, !want)
		}
	}
}

func TestDecide(t *testing.T) {
	at := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	sni := Attempt{Connect: OK, Handshake: Reset}
	tried := []Tried{{"split-1-midsld", sni}, {"disorder-1-midsld", opened}, {"fake-md5-split", opened}}
	cases := []struct {
		name            string
		direct, control Attempt
		tried           []Tried
		method          Method
		strategy        string
	}{
		{"opens directly", opened, okCtl, tried, MethodDirect, ""},
		{"first working strategy wins", sni, okCtl, tried, MethodDPI, "disorder-1-midsld"},
		{"no strategy helps", sni, okCtl, tried[:1], MethodElsewhere, ""},
		{"ip block: strategies are not even looked at", Attempt{Connect: Timeout}, okCtl, tried, MethodElsewhere, ""},
		{"link bad", sni, Attempt{Connect: Timeout}, tried, MethodUnknown, ""},
	}
	for _, c := range cases {
		v := Decide(c.direct, c.control, c.tried, at)
		if v.Method != c.method || v.Strategy != c.strategy || !v.CheckedAt.Equal(at) {
			t.Errorf("%s: %+v, want %s %q", c.name, v, c.method, c.strategy)
		}
	}
}

func TestRankingAndRotation(t *testing.T) {
	now := time.Now()
	order := []string{"a", "b", "c", "d", "e"}
	scores := []Score{
		{Strategy: "e", Opened: 3, Failed: 0, LastOK: now},
		{Strategy: "c", Opened: 3, Failed: 1, LastOK: now},
		{Strategy: "b", Opened: 3, Failed: 0, LastOK: now.Add(-time.Hour)},
		{Strategy: "a", Opened: 3, Failed: 0, LastOK: now},
		{Strategy: "d", Opened: 0, Failed: 3},
	}
	var got []string
	for _, s := range Ranking(scores, order) {
		got = append(got, s.Strategy)
	}
	// a и e равны во всём — раньше та, что раньше в каталоге.
	if want := []string{"a", "e", "b", "c", "d"}; !slices.Equal(got, want) {
		t.Errorf("ranking %v, want %v", got, want)
	}
	if r := Rotation(Ranking(scores, order), 4); !slices.Equal(r, []string{"a", "e", "b", "c"}) {
		t.Errorf("rotation %v", r)
	}
	if r := Rotation([]Score{{Strategy: "x"}}, 3); len(r) != 0 {
		t.Errorf("useless strategy in rotation: %v", r)
	}
}

func TestPacer(t *testing.T) {
	p := NewPacer()
	t0 := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	if !p.Allow("x.example", t0) || !p.Allow("x.example", t0.Add(10*time.Second)) {
		t.Fatal("first two refused")
	}
	if p.Allow("x.example", t0.Add(20*time.Second)) {
		t.Error("third within a minute allowed")
	}
	if !p.Allow("y.example", t0.Add(20*time.Second)) {
		t.Error("another name refused")
	}
	if w := p.Wait("x.example", t0.Add(20*time.Second)); w != 40*time.Second {
		t.Errorf("wait %v, want 40s", w)
	}
	if !p.Allow("x.example", t0.Add(61*time.Second)) {
		t.Error("after the window refused")
	}
}

func TestCheckDue(t *testing.T) {
	p := DefaultCheckParams()
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	fresh := &Verdict{Method: MethodDPI, CheckedAt: now.Add(-time.Hour)}
	old := &Verdict{Method: MethodDirect, CheckedAt: now.Add(-25 * time.Hour)}
	unknown := &Verdict{Method: MethodUnknown, CheckedAt: now.Add(-20 * time.Minute)}
	cases := []struct {
		name     string
		v        *Verdict
		lastUsed time.Time
		want     bool
	}{
		{"just asked, no verdict", nil, now, true},
		{"never used lately: list domain stays unchecked", nil, now.Add(-4 * 24 * time.Hour), false},
		{"fresh verdict", fresh, now, false},
		{"stale verdict, in use", old, now.Add(-time.Hour), true},
		{"stale verdict, not used", old, now.Add(-5 * 24 * time.Hour), false},
		{"unknown retried soon", unknown, now, true},
	}
	for _, c := range cases {
		if got := CheckDue(c.v, c.lastUsed, now, p); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}

func TestRunAllowed(t *testing.T) {
	for _, r := range []RunReason{RunNoStrategy, RunAddressChanged, RunDaily, RunRotationExhausted} {
		if !RunAllowed(model.LinkKindWired, r) || RunAllowed(model.LinkKindLTE, r) {
			t.Errorf("%s: wired must run, LTE must not", r)
		}
	}
	if !RunAllowed(model.LinkKindLTE, RunManual) {
		t.Error("manual run on LTE refused")
	}
}
