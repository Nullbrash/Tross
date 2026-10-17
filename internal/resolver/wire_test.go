package resolver

import (
	"bytes"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Ответ с подписью (тип, которого dnsmessage не знает) и OPT: TTL правятся
// у записей, флаги OPT и байты подписи — нет.
func TestForClientKeepsSignaturesAndOPT(t *testing.T) {
	name := dnsmessage.MustNewName("signed.example.")
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, Response: true})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	_ = b.StartAnswers()
	_ = b.AResource(dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET, TTL: 300}, dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}})
	sig := []byte{0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4}
	_ = b.UnknownResource(dnsmessage.ResourceHeader{Name: name, Type: 46, Class: dnsmessage.ClassINET, TTL: 300}, dnsmessage.UnknownResource{Type: 46, Data: sig})
	_ = b.StartAdditionals()
	var opt dnsmessage.ResourceHeader
	_ = opt.SetEDNS0(1232, dnsmessage.RCodeSuccess, true)
	_ = b.OPTResource(opt, dnsmessage.OPTResource{})
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	out, err := forClient(msg, 77, 100*time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	var m dnsmessage.Message
	if err := m.Unpack(out); err != nil {
		t.Fatal(err)
	}
	if m.ID != 77 || m.Answers[0].Header.TTL != 200 || m.Answers[1].Header.TTL != 200 {
		t.Errorf("id %d, ttls %d %d", m.ID, m.Answers[0].Header.TTL, m.Answers[1].Header.TTL)
	}
	if !bytes.Contains(out, sig) {
		t.Error("signature bytes changed")
	}
	if !m.Additionals[0].Header.DNSSECAllowed() {
		t.Error("OPT flags (DO) were rewritten as a TTL")
	}
	// Старше срока — не меньше 1 с; фиксированный срок — для устаревших.
	out, _ = forClient(msg, 1, time.Hour, 0)
	_ = m.Unpack(out)
	if m.Answers[0].Header.TTL != 1 {
		t.Errorf("expired ttl %d, want 1", m.Answers[0].Header.TTL)
	}
	out, _ = forClient(msg, 1, 0, staleTTL)
	_ = m.Unpack(out)
	if m.Answers[0].Header.TTL != staleTTL {
		t.Errorf("stale ttl %d", m.Answers[0].Header.TTL)
	}
	if _, err := forClient(msg[:20], 1, 0, 0); err == nil {
		t.Error("truncated message accepted")
	}
}

// Свой запрос: только EDNS без опций (без подсети клиента), DO — как просил.
func TestBuildQueryNoECS(t *testing.T) {
	for _, do := range []bool{false, true} {
		q, err := buildQuery(5, "example.com", dnsmessage.TypeA, do)
		if err != nil {
			t.Fatal(err)
		}
		var m dnsmessage.Message
		if err := m.Unpack(q); err != nil {
			t.Fatal(err)
		}
		opt, ok := m.Additionals[0].Body.(*dnsmessage.OPTResource)
		if len(m.Additionals) != 1 || !ok || len(opt.Options) != 0 || m.Additionals[0].Header.DNSSECAllowed() != do {
			t.Errorf("do=%v: additionals %+v", do, m.Additionals)
		}
		if !m.RecursionDesired || m.Questions[0].Name.String() != "example.com." {
			t.Errorf("header %+v", m.Header)
		}
	}
}

func TestInspect(t *testing.T) {
	name := dnsmessage.MustNewName("gone.example.")
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, Response: true, RCode: dnsmessage.RCodeNameError})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	_ = b.StartAuthorities()
	_ = b.SOAResource(dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("example."), Class: dnsmessage.ClassINET, TTL: 900},
		dnsmessage.SOAResource{NS: name, MBox: name, MinTTL: 120})
	msg, _ := b.Finish()
	a, err := inspect(msg, "gone.example", dnsmessage.TypeA)
	if err != nil || !a.Empty() || a.TTL != 120*time.Second {
		t.Errorf("negative: %+v %v — want empty, ttl from SOA minimum", a, err)
	}
	if _, err := inspect(msg, "other.example", dnsmessage.TypeA); err == nil {
		t.Error("answer for another question accepted")
	}
}

func TestParseQuery(t *testing.T) {
	q, err := parseQuery(mkQuery(t, 9, "WWW.Example.COM", dnsmessage.TypeA, true))
	if err != nil || q.Name != "www.example.com" || q.UDPSize != 1232 || q.ID != 9 {
		t.Errorf("%+v %v", q, err)
	}
	resp := reply(q, dnsmessage.RCodeSuccess, false)
	if _, err := parseQuery(resp); err == nil {
		t.Error("response parsed as a query")
	}
	if _, err := parseQuery([]byte{1, 2, 3}); err == nil {
		t.Error("garbage parsed")
	}
}
