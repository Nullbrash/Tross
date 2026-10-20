package main

import (
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestDNSAnswer(t *testing.T) {
	ans := netip.MustParseAddr("203.0.113.10")
	for _, qt := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 42, RecursionDesired: true})
		_ = b.StartQuestions()
		_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("check.lab."), Type: qt, Class: dnsmessage.ClassINET})
		q, _ := b.Finish()
		raw, err := dnsAnswer(q, ans)
		if err != nil {
			t.Fatal(err)
		}
		var m dnsmessage.Message
		if err := m.Unpack(raw); err != nil {
			t.Fatal(err)
		}
		if m.ID != 42 || !m.Response || len(m.Questions) != 1 {
			t.Fatalf("%v: header %+v", qt, m.Header)
		}
		switch {
		case qt == dnsmessage.TypeA && (len(m.Answers) != 1 || m.Answers[0].Body.(*dnsmessage.AResource).A != ans.As4()):
			t.Fatalf("A answer = %+v", m.Answers)
		case qt == dnsmessage.TypeAAAA && len(m.Answers) != 0:
			t.Fatalf("AAAA must be empty, got %+v", m.Answers)
		}
	}
}

func TestDNSBehaviours(t *testing.T) {
	query := func(name string) []byte {
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7})
		_ = b.StartQuestions()
		_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
		q, _ := b.Finish()
		return q
	}
	ask := func(spec, name string) *dnsmessage.Message {
		t.Helper()
		b, err := parseBehavior(spec)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := b.reply(query(name))
		if err != nil {
			t.Fatal(err)
		}
		if raw == nil {
			return nil
		}
		var m dnsmessage.Message
		if err := m.Unpack(raw); err != nil {
			t.Fatal(err)
		}
		return &m
	}
	a := func(m *dnsmessage.Message) [4]byte { return m.Answers[0].Body.(*dnsmessage.AResource).A }
	if x, y := a(ask("hash", "a.example.")), a(ask("hash", "A.Example.")); x != y || x[0] != 198 || x[3] == 0 || x[3] == 255 {
		t.Errorf("hash: %v %v (same name — same address in 198.51.100.1–254)", x, y)
	}
	if a(ask("hash", "a.example.")) == a(ask("hash", "b.example.")) {
		t.Error("hash: different names share an address")
	}
	if m := ask("answer:203.0.113.250", "x.example."); a(m) != [4]byte{203, 0, 113, 250} {
		t.Errorf("answer: %v", a(m))
	}
	if m := ask("servfail", "x.example."); m.RCode != dnsmessage.RCodeServerFailure || len(m.Answers) != 0 {
		t.Errorf("servfail: %v %v", m.RCode, m.Answers)
	}
	if m := ask("drop", "x.example."); m != nil {
		t.Error("drop answered")
	}
	start := time.Now()
	ask("hash/50ms", "x.example.")
	if time.Since(start) < 50*time.Millisecond {
		t.Error("delay not applied")
	}
	for _, bad := range []string{"nope", "answer:", "answer:::1", "hash/x"} {
		if _, err := parseBehavior(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
