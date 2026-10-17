package resolver

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// query — запрос клиента.
type query struct {
	ID       uint16
	Name     string // нижний регистр, без завершающей точки
	Type     dnsmessage.Type
	Class    dnsmessage.Class
	RD       bool
	DO       bool   // клиент просит подписи DNSSEC
	UDPSize  uint16 // сколько клиент примет по UDP
	question dnsmessage.Question
}

var errNotQuery = errors.New("not a standard query with one question")

func parseQuery(b []byte) (query, error) {
	var p dnsmessage.Parser
	h, err := p.Start(b)
	if err != nil {
		return query{}, err
	}
	if h.Response || h.OpCode != 0 {
		return query{}, errNotQuery
	}
	qs, err := p.AllQuestions()
	if err != nil || len(qs) != 1 {
		return query{ID: h.ID}, errNotQuery
	}
	q := query{ID: h.ID, RD: h.RecursionDesired, UDPSize: 512, question: qs[0], Type: qs[0].Type, Class: qs[0].Class}
	q.Name = strings.ToLower(strings.TrimSuffix(qs[0].Name.String(), "."))
	if err := p.SkipAllAnswers(); err != nil {
		return q, nil
	}
	if err := p.SkipAllAuthorities(); err != nil {
		return q, nil
	}
	for {
		rh, err := p.AdditionalHeader()
		if err != nil {
			break
		}
		if rh.Type == dnsmessage.TypeOPT {
			q.UDPSize = max(uint16(rh.Class), 512)
			q.DO = rh.DNSSECAllowed()
		}
		if err := p.SkipAdditional(); err != nil {
			break
		}
	}
	return q, nil
}

// buildQuery — свой запрос наружу: без подсети клиента (ECS) — сервер не
// узнает район дома; DO — как у клиента, чтобы подписи DNSSEC дошли до
// проверяющих их устройств.
func buildQuery(id uint16, name string, t dnsmessage.Type, do bool) ([]byte, error) {
	n, err := dnsmessage.NewName(name + ".")
	if err != nil {
		return nil, err
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: t, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	if err := b.StartAdditionals(); err != nil {
		return nil, err
	}
	var rh dnsmessage.ResourceHeader
	if err := rh.SetEDNS0(1232, dnsmessage.RCodeSuccess, do); err != nil {
		return nil, err
	}
	if err := b.OPTResource(rh, dnsmessage.OPTResource{}); err != nil {
		return nil, err
	}
	return b.Finish()
}

// answer — что важно резолверу в ответе сервера.
type answer struct {
	RCode dnsmessage.RCode
	Addrs []netip.Addr
	// TTL — наименьший у записей ответа; у отрицательного — из SOA.
	TTL       time.Duration
	Truncated bool
	// Records — записей в разделе ответа.
	Records int
}

// Empty — ответ без адресов и записей (для гонки — «пустой»).
func (a answer) Empty() bool {
	return a.RCode == dnsmessage.RCodeNameError || a.RCode == dnsmessage.RCodeSuccess && a.Records == 0
}

// negativeTTL — срок отрицательного ответа без SOA.
const negativeTTL = 60 * time.Second

// inspect — разбор ответа; вопрос должен совпасть с заданным (ответ не на
// тот запрос — сбой сервера, а не данные).
func inspect(resp []byte, name string, t dnsmessage.Type) (answer, error) {
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil {
		return answer{}, err
	}
	a := answer{RCode: h.RCode, Truncated: h.Truncated}
	qs, err := p.AllQuestions()
	if err != nil {
		return a, err
	}
	if len(qs) != 1 || qs[0].Type != t || !strings.EqualFold(strings.TrimSuffix(qs[0].Name.String(), "."), name) {
		return a, errors.New("answer for another question")
	}
	ttl, records := uint32(0), 0
	for {
		rh, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return a, err
		}
		if records == 0 || rh.TTL < ttl {
			ttl = rh.TTL
		}
		records++
		if rh.Type == dnsmessage.TypeA {
			r, err := p.AResource()
			if err != nil {
				return a, err
			}
			a.Addrs = append(a.Addrs, netip.AddrFrom4(r.A))
			continue
		}
		if err := p.SkipAnswer(); err != nil {
			return a, err
		}
	}
	if records > 0 {
		a.TTL, a.Records = time.Duration(ttl)*time.Second, records
		return a, nil
	}
	a.TTL = negativeTTL
	for {
		rh, err := p.AuthorityHeader()
		if err != nil {
			break
		}
		if rh.Type != dnsmessage.TypeSOA {
			if p.SkipAuthority() != nil {
				break
			}
			continue
		}
		soa, err := p.SOAResource()
		if err == nil {
			a.TTL = time.Duration(min(rh.TTL, soa.MinTTL)) * time.Second
		}
		break
	}
	return a, nil
}

// forClient — ответ сервера клиенту: его ID, TTL записей уменьшены на
// возраст ответа в кэше (не меньше 1) или заменены на fixed. Правка — по
// байтам: остальное (подписи DNSSEC) доходит до клиента нетронутым.
func forClient(resp []byte, id uint16, age time.Duration, fixed uint32) ([]byte, error) {
	out := append([]byte(nil), resp...)
	binary.BigEndian.PutUint16(out, id)
	dec := uint32(age / time.Second)
	err := walkTTL(out, func(ttl uint32) uint32 {
		if fixed > 0 {
			return fixed
		}
		if ttl <= dec {
			return 1
		}
		return ttl - dec
	})
	return out, err
}

var errMalformed = errors.New("malformed message")

// walkTTL — каждая запись ответа, кроме OPT (у неё в поле TTL — флаги).
func walkTTL(msg []byte, fn func(uint32) uint32) error {
	if len(msg) < 12 {
		return errMalformed
	}
	be := binary.BigEndian
	qd := int(be.Uint16(msg[4:]))
	rr := int(be.Uint16(msg[6:])) + int(be.Uint16(msg[8:])) + int(be.Uint16(msg[10:]))
	off := 12
	var err error
	for range qd {
		if off, err = skipName(msg, off); err != nil {
			return err
		}
		off += 4
	}
	for range rr {
		if off, err = skipName(msg, off); err != nil {
			return err
		}
		if off+10 > len(msg) {
			return errMalformed
		}
		typ, rdlen := be.Uint16(msg[off:]), int(be.Uint16(msg[off+8:]))
		if dnsmessage.Type(typ) != dnsmessage.TypeOPT {
			be.PutUint32(msg[off+4:], fn(be.Uint32(msg[off+4:])))
		}
		off += 10 + rdlen
		if off > len(msg) {
			return errMalformed
		}
	}
	return nil
}

func skipName(msg []byte, off int) (int, error) {
	for {
		if off >= len(msg) {
			return 0, errMalformed
		}
		l := int(msg[off])
		switch {
		case l == 0:
			return off + 1, nil
		case l&0xc0 == 0xc0:
			return off + 2, nil
		}
		off += 1 + l
	}
}

// reply — ответ без записей: код и вопрос клиента. tc — «повтори по TCP».
func reply(q query, rcode dnsmessage.RCode, tc bool) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: q.ID, Response: true, RecursionDesired: q.RD, RecursionAvailable: true, RCode: rcode, Truncated: tc})
	if q.Name != "" || q.question.Type != 0 {
		_ = b.StartQuestions()
		_ = b.Question(q.question)
	}
	out, err := b.Finish()
	if err != nil {
		// Вопрос не собрался (не наш формат) — одна шапка.
		out = make([]byte, 12)
		binary.BigEndian.PutUint16(out, q.ID)
		out[2] = 0x80
		out[3] = 0x80 | byte(rcode&0xf)
	}
	return out
}
