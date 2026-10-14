package main

import (
	"net/netip"
	"testing"

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
