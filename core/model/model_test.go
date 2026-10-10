package model

import (
	"encoding/json"
	"testing"
	"time"
)

func TestMACRandomized(t *testing.T) {
	cases := []struct {
		mac    string
		random bool
	}{
		{"00:1a:2b:3c:4d:5e", false},
		{"f0:18:98:00:00:01", false},
		{"02:00:00:00:00:01", true},
		{"a6:11:22:33:44:55", true},
		{"DA:11:22:33:44:55", true},
		{"ee:11:22:33:44:55", true},
		{"03:00:00:00:00:01", false}, // multicast, не клиентский адрес
	}
	for _, c := range cases {
		m, err := ParseMAC(c.mac)
		if err != nil {
			t.Fatalf("ParseMAC(%q): %v", c.mac, err)
		}
		if got := m.IsRandomized(); got != c.random {
			t.Errorf("%s: IsRandomized = %v, want %v", c.mac, got, c.random)
		}
	}
}

func TestParseMACRejectsEUI64(t *testing.T) {
	if _, err := ParseMAC("00:00:00:00:fe:80:00:00"); err == nil {
		t.Fatal("expected error for 8-byte address")
	}
}

func TestMACJSONRoundTrip(t *testing.T) {
	m, _ := ParseMAC("AA:BB:CC:00:11:22")
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `"aa:bb:cc:00:11:22"` {
		t.Fatalf("marshal = %s", b)
	}
	var back MAC
	if err := json.Unmarshal(b, &back); err != nil || back != m {
		t.Fatalf("unmarshal = %v, %v", back, err)
	}
}

func TestNormalizeDomain(t *testing.T) {
	good := map[string]string{
		"Example.COM.":       "example.com",
		" sub.example.com ":  "sub.example.com",
		"xn--80ak6aa92e.com": "xn--80ak6aa92e.com",
	}
	for in, want := range good {
		got, err := NormalizeDomain(in)
		if err != nil || got != want {
			t.Errorf("NormalizeDomain(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", ".", "a..b", "exa mple.com", "пример.рф"} {
		if _, err := NormalizeDomain(bad); err == nil {
			t.Errorf("NormalizeDomain(%q): expected error", bad)
		}
	}
}

func TestDomainRuleMatches(t *testing.T) {
	suffix := DomainRule{Pattern: "example.com", Match: MatchSuffix}
	exact := DomainRule{Pattern: "example.com", Match: MatchExact}
	kw := DomainRule{Pattern: "googlevideo", Match: MatchKeyword}

	checks := []struct {
		rule   DomainRule
		domain string
		want   bool
	}{
		{suffix, "example.com", true},
		{suffix, "a.b.example.com", true},
		{suffix, "badexample.com", false},
		{exact, "example.com", true},
		{exact, "www.example.com", false},
		{kw, "rr1---sn-abc.googlevideo.com", true},
	}
	for _, c := range checks {
		if got := c.rule.Matches(c.domain); got != c.want {
			t.Errorf("%s %s vs %q = %v, want %v", c.rule.Match, c.rule.Pattern, c.domain, got, c.want)
		}
	}
}

func TestDomainRulePrecedence(t *testing.T) {
	online := DomainRule{Pattern: "www.example.com", Match: MatchExact, Layer: LayerOnline}
	learned := DomainRule{Pattern: "example.com", Match: MatchSuffix, Layer: LayerLearned}
	manual := DomainRule{Pattern: "com", Match: MatchSuffix, Layer: LayerManual}

	if !manual.Precedes(learned) || !learned.Precedes(online) {
		t.Fatal("layer order must be manual > learned > online")
	}
	longer := DomainRule{Pattern: "a.example.com", Match: MatchSuffix, Layer: LayerOnline}
	shorter := DomainRule{Pattern: "example.com", Match: MatchSuffix, Layer: LayerOnline}
	if !longer.Precedes(shorter) || shorter.Precedes(longer) {
		t.Fatal("within a layer the more specific pattern must win")
	}
	if !online.Precedes(DomainRule{Pattern: "www.example.com", Match: MatchSuffix, Layer: LayerOnline}) {
		t.Fatal("exact must win over suffix of the same pattern")
	}
}

func TestDomainRuleValidate(t *testing.T) {
	ok := DomainRule{Pattern: "example.com", Match: MatchSuffix, Layer: LayerOnline, Source: "itdog"}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid rule: %v", err)
	}
	bad := []DomainRule{
		{Pattern: "Example.com", Match: MatchSuffix, Layer: LayerManual},
		{Pattern: "example.com", Match: "regex", Layer: LayerManual},
		{Pattern: "example.com", Match: MatchExact, Layer: LayerManual, Method: MethodAuto},
		{Pattern: "example.com", Match: MatchExact, Layer: LayerManual, Method: MethodProxy},
	}
	for i, r := range bad {
		if err := r.Validate(); err == nil {
			t.Errorf("bad[%d]: expected error", i)
		}
	}
}

func TestPolicyValidate(t *testing.T) {
	p := Policy{
		Selector:   SelectLowestLatency,
		Stickiness: StickSession,
		StickyTTL:  30 * time.Minute,
		Links:      []LinkID{"isp1", "isp2"},
		Fallback:   []LinkID{"lte"},
		Method:     MethodDirect,
		Priority:   PriorityHigh,
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("valid policy: %v", err)
	}
	q := p
	q.Fallback = []LinkID{"isp1"}
	if q.Validate() == nil {
		t.Error("link in both links and fallback must be rejected")
	}
	q = p
	q.StickyTTL = 0
	if q.Validate() == nil {
		t.Error("sticky policy without ttl must be rejected")
	}
	q = p
	q.Method = MethodProxy
	if q.Validate() == nil {
		t.Error("proxy method without allow_proxy must be rejected")
	}
}

func TestDecisionValidate(t *testing.T) {
	ok := Decision{Link: "isp1", Method: MethodProxy, ProxyID: "nl-1", Class: ClassDefault}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid decision: %v", err)
	}
	bad := []Decision{
		{Method: MethodDirect},
		{Link: "isp1", Method: MethodAuto},
		{Link: "isp1", Method: MethodProxy},
		{Link: "isp1", Method: MethodDirect, ProxyID: "nl-1"},
		{Link: "isp1", Method: MethodDirect, Sticky: true},
	}
	for i, d := range bad {
		if d.Validate() == nil {
			t.Errorf("bad[%d]: expected error", i)
		}
	}
}

func TestLinkStateUsable(t *testing.T) {
	usable := map[LinkState]bool{
		LinkStateUp: true, LinkStateDegraded: true,
		LinkStateDown: false, LinkStateUnknown: false, LinkStateRestricted: false,
	}
	for s, want := range usable {
		if s.Usable() != want {
			t.Errorf("%s.Usable() = %v, want %v", s, s.Usable(), want)
		}
	}
}

func TestLinkHealthValidate(t *testing.T) {
	h := LinkHealth{LinkID: "isp1", State: LinkStateUp, RTT: 5 * time.Millisecond, Loss: 0.01}
	if err := h.Validate(); err != nil {
		t.Fatalf("valid health: %v", err)
	}
	h.Loss = 1.5
	if h.Validate() == nil {
		t.Error("loss > 1 must be rejected")
	}
}

func TestProxyURINotSerialized(t *testing.T) {
	b, _ := json.Marshal(ProxyOutbound{ID: "p1", URI: "vless://secret@host:443"})
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if _, ok := m["URI"]; ok {
		t.Fatal("proxy URI must never be serialized")
	}
	if _, ok := m["uri"]; ok {
		t.Fatal("proxy URI must never be serialized")
	}
}
