package api

import (
	"cmp"
	"context"
	"errors"
	"net/http"
	"net/netip"
	"slices"
	"strconv"

	"tross/core/model"
	"tross/core/sqm"
	"tross/internal/dataplane"
)

const (
	defaultConnections = 200
	maxConnections     = 5000
)

// connDTO — соединение для интерфейса (сроки в секундах).
type connDTO struct {
	Proto    string             `json:"proto"`
	Src      netip.AddrPort     `json:"src"`
	Dst      netip.AddrPort     `json:"dst"`
	Link     model.LinkID       `json:"link,omitempty"`
	Class    model.TrafficClass `json:"class,omitempty"`
	Forward  netip.AddrPort     `json:"forward,omitzero"`
	Tin      string             `json:"tin,omitempty"`
	State    string             `json:"state,omitempty"`
	TimeoutS int64              `json:"timeout_s"`
	Packets  uint64             `json:"packets"`
	Bytes    uint64             `json:"bytes"`
}

// tinName — корзина для API; без корзины — пусто (CAKE решает по DSCP).
func tinName(t sqm.Tin) string {
	if t == sqm.TinNone {
		return ""
	}
	return t.String()
}

func toConnDTO(c dataplane.Connection) connDTO {
	return connDTO{
		Proto: c.Proto, Src: c.Src, Dst: c.Dst, Link: c.Link, Class: c.Class, Forward: c.Forward, Tin: tinName(c.Tin), State: c.State,
		TimeoutS: int64(c.Timeout.Seconds()), Packets: c.Packets, Bytes: c.Bytes,
	}
}

// handleConnections — снимок conntrack на момент запроса: сводка по классам
// и каналам считается по всем подходящим соединениям, список — до limit
// самых объёмных.
func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	if s.opts.Connections == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "connections are not available"})
		return
	}
	limit, err := intParam(r, "limit", defaultConnections, maxConnections)
	if err != nil {
		badRequest(w, err)
		return
	}
	q := r.URL.Query()
	var device netip.Addr
	if v := q.Get("device"); v != "" {
		if device, err = netip.ParseAddr(v); err != nil {
			badRequest(w, errors.New("device: IPv4 address expected"))
			return
		}
	}
	class, link := model.TrafficClass(q.Get("class")), model.LinkID(q.Get("link"))
	conns, err := s.opts.Connections(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	byClass, byLink := map[model.TrafficClass]int{}, map[model.LinkID]int{}
	var match []dataplane.Connection
	for _, c := range conns {
		if device.IsValid() && c.Src.Addr() != device || class != "" && c.Class != class || link != "" && c.Link != link {
			continue
		}
		match = append(match, c)
		byClass[c.Class]++
		byLink[c.Link]++
	}
	slices.SortFunc(match, func(a, b dataplane.Connection) int {
		return cmp.Or(cmp.Compare(b.Bytes, a.Bytes), cmp.Compare(a.Src.String(), b.Src.String()), cmp.Compare(a.Dst.String(), b.Dst.String()))
	})
	out := make([]connDTO, 0, min(len(match), limit))
	for _, c := range match[:min(len(match), limit)] {
		out = append(out, toConnDTO(c))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"total": len(match), "by_class": byClass, "by_link": byLink, "connections": out,
	})
}

// Explanation — ответ «почему так» для соединения, которое ещё не открыто.
type Explanation struct {
	Flow           model.Flow           `json:"flow"`
	Classification model.Classification `json:"classification"`
	// Shares — доли каналов класса в ядре сейчас; пусто — плана ещё нет
	// или ни один разрешённый классу канал не пригоден.
	Shares []ShareDTO `json:"shares"`
	// Pin — действующее закрепление в ядре, которое определит канал.
	Pin *PinDTO `json:"pin,omitempty"`
	// Link — канал, если он определён однозначно (закрепление или одна доля);
	// при нескольких долях выбор делает ядро по хешу адресов.
	Link   model.LinkID `json:"link,omitempty"`
	Method model.Method `json:"method,omitempty"`
	// Tin — корзина очереди CAKE класса (голос, видео, обычное, фон).
	Tin    string `json:"tin,omitempty"`
	Reason string `json:"reason"`
	// Existing — уже открытые соединения этого устройства к тому же адресу.
	Existing []connDTO `json:"existing"`
	// Notes — какие входные данные ядро учтёт, а какие нет.
	Notes []string `json:"notes"`
}

type ShareDTO struct {
	Link   model.LinkID `json:"link"`
	Weight int          `json:"weight"`
}

type PinDTO struct {
	Kind     model.Stickiness `json:"kind"`
	Link     model.LinkID     `json:"link"`
	ExpiresS int64            `json:"expires_s"`
}

// ExplainFunc — объяснение решения; Existing заполняет сам сервер.
type ExplainFunc func(ctx context.Context, f model.Flow) (Explanation, error)

// handleExplain — src обязателен (устройство: закрепления — по нему); dst —
// адрес или адрес:порт; без dst нужен domain.
func (s *Server) handleExplain(w http.ResponseWriter, r *http.Request) {
	if s.opts.Explain == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "explain is not available"})
		return
	}
	f, err := flowQuery(r)
	if err != nil {
		badRequest(w, err)
		return
	}
	ex, err := s.opts.Explain(r.Context(), f)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	ex.Existing = []connDTO{}
	if s.opts.Connections != nil && f.Dst.Addr().IsValid() {
		conns, err := s.opts.Connections(r.Context())
		if err != nil {
			ex.Notes = append(ex.Notes, "existing connections unavailable: "+err.Error())
		}
		for _, c := range conns {
			if c.Src.Addr() == f.Src.Addr() && c.Dst.Addr() == f.Dst.Addr() && (f.Dst.Port() == 0 || c.Dst.Port() == f.Dst.Port()) {
				ex.Existing = append(ex.Existing, toConnDTO(c))
			}
		}
	}
	ex.Shares, ex.Notes = nonNil(ex.Shares), nonNil(ex.Notes)
	writeJSON(w, http.StatusOK, ex)
}

func flowQuery(r *http.Request) (model.Flow, error) {
	q := r.URL.Query()
	f := model.Flow{Proto: model.Protocol(cmp.Or(q.Get("proto"), string(model.ProtoTCP))), Signature: q.Get("signature")}
	if f.Proto != model.ProtoTCP && f.Proto != model.ProtoUDP {
		return f, errors.New("proto: tcp or udp expected")
	}
	src, err := netip.ParseAddr(q.Get("src"))
	if err != nil || !src.Is4() {
		return f, errors.New("src: device IPv4 address expected")
	}
	f.Src = netip.AddrPortFrom(src, 0)
	if v := q.Get("domain"); v != "" {
		d, err := model.NormalizeDomain(v)
		if err != nil {
			return f, errors.New("domain: " + err.Error())
		}
		f.Domain = d
	}
	if v := q.Get("dst"); v != "" {
		ap, err := netip.ParseAddrPort(v)
		if err != nil {
			a, aerr := netip.ParseAddr(v)
			if aerr != nil {
				return f, errors.New("dst: IPv4 address or address:port expected")
			}
			ap = netip.AddrPortFrom(a, 0)
		}
		if !ap.Addr().Is4() {
			return f, errors.New("dst: IPv4 address expected")
		}
		f.Dst = ap
	} else if f.Domain == "" {
		return f, errors.New("dst or domain required")
	}
	if v := q.Get("port"); v != "" {
		p, err := strconv.ParseUint(v, 10, 16)
		if err != nil || p == 0 {
			return f, errors.New("port: 1-65535 expected")
		}
		f.Dst = netip.AddrPortFrom(f.Dst.Addr(), uint16(p))
	}
	return f, nil
}
